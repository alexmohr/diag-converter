//! YAML document -> canonical IR transformation.
//!
//! Parses a YAML string into the YAML model, then transforms it into the
//! canonical DiagDatabase IR used by all other converters.

use crate::yaml_model::*;
use diag_ir::*;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, thiserror::Error)]
pub enum YamlParseError {
    #[error("YAML deserialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

/// Serialize a serde_yaml::Value to a canonical JSON string with sorted keys.
/// This ensures that round-tripping through YAML doesn't change key order.
fn canonical_json(val: &serde_yaml::Value) -> String {
    // serde_json::Value uses BTreeMap for objects, so keys are sorted.
    let json_val: serde_json::Value = serde_json::to_value(val).unwrap_or_default();
    serde_json::to_string(&json_val).unwrap_or_default()
}

/// Convert a per-service YAML audience to the IR Audience type.
fn yaml_service_audience_to_ir(a: &YamlServiceAudience) -> Audience {
    let mut enabled = Vec::new();
    for g in &a.groups {
        enabled.push(AdditionalAudience {
            short_name: g.clone(),
            long_name: None,
        });
    }
    Audience {
        enabled_audiences: enabled,
        disabled_audiences: vec![],
        is_supplier: a.supplier.unwrap_or(false),
        is_development: a.development.unwrap_or(false),
        is_manufacturing: a.manufacturing.unwrap_or(false),
        is_after_sales: a.after_sales.unwrap_or(false),
        is_after_market: a.after_market.unwrap_or(false),
    }
}

/// Parse a YAML string into a DiagDatabase IR.
pub fn parse_yaml(yaml: &str) -> Result<DiagDatabase, YamlParseError> {
    let doc: YamlDocument = serde_yaml::from_str(yaml)?;
    yaml_to_ir(&doc)
}

/// Transform a parsed YAML document into the canonical IR.
#[allow(clippy::unnecessary_wraps)]
fn yaml_to_ir(doc: &YamlDocument) -> Result<DiagDatabase, YamlParseError> {
    let ecu = doc.ecu.as_ref();
    let ecu_name = ecu.map(|e| e.name.clone()).unwrap_or_default();
    let ecu_id = ecu.map(|e| e.id.clone()).unwrap_or_default();

    let revision = doc
        .meta
        .as_ref()
        .map(|m| m.revision.clone())
        .unwrap_or_default();

    let version = doc
        .meta
        .as_ref()
        .map(|m| m.version.clone())
        .unwrap_or_default();

    // Build metadata from meta section
    let mut metadata = BTreeMap::new();
    if let Some(meta) = &doc.meta {
        if !meta.author.is_empty() {
            metadata.insert("author".into(), meta.author.clone());
        }
        if !meta.domain.is_empty() {
            metadata.insert("domain".into(), meta.domain.clone());
        }
        if !meta.created.is_empty() {
            metadata.insert("created".into(), meta.created.clone());
        }
        if !meta.description.is_empty() {
            metadata.insert("description".into(), meta.description.clone());
        }
    }
    if !ecu_id.is_empty() {
        metadata.insert("ecu_id".into(), ecu_id);
    }
    metadata.insert("schema".into(), doc.schema.clone());

    // Build named type registry for resolving type references in DIDs
    let type_registry = build_type_registry(doc.types.as_ref());

    // Store type definitions in IR for roundtrip
    let type_definitions: Vec<TypeDefinition> = doc
        .types
        .as_ref()
        .map(|types| {
            types
                .iter()
                .map(|(name, yt)| TypeDefinition {
                    name: name.clone(),
                    base: yt.base.clone(),
                    bit_length: yt.bit_length,
                    min_length: yt.min_length,
                    max_length: yt.max_length,
                    enum_values_json: yt
                        .enum_values
                        .as_ref()
                        .and_then(|v| serde_json::to_string(v).ok()),
                    description: None,
                })
                .collect()
        })
        .unwrap_or_default();

    // Build access pattern lookup for resolving DID/routine access references
    let access_patterns = build_access_pattern_lookup(
        doc.access_patterns.as_ref(),
        doc.sessions.as_ref(),
        doc.security.as_ref(),
        doc.authentication.as_ref(),
    );

    // Build services from DID definitions + enabled standard services
    let mut diag_services = Vec::new();

    // Generate ReadDataByIdentifier services from DIDs
    if let Some(serde_yaml::Value::Mapping(dids)) = &doc.dids {
        for (key, val) in dids {
            let did_id = parse_hex_key(key);
            if let Ok(did) = serde_yaml::from_value::<Did>(val.clone()) {
                if did.readable.unwrap_or(true) {
                    let mut svc = did_to_read_service(did_id, &did, &type_registry);
                    apply_access_pattern(&mut svc.diag_comm, &did.access, &access_patterns);
                    diag_services.push(svc);
                }
                if did.writable.unwrap_or(false) {
                    let mut svc = did_to_write_service(did_id, &did, &type_registry);
                    apply_access_pattern(&mut svc.diag_comm, &did.access, &access_patterns);
                    diag_services.push(svc);
                }
            }
        }
    }

    // Generate RoutineControl services from routines
    if let Some(serde_yaml::Value::Mapping(routines)) = &doc.routines {
        for (key, val) in routines {
            let rid = parse_hex_key(key);
            if let Ok(routine) = serde_yaml::from_value::<Routine>(val.clone()) {
                let mut svc = routine_to_service(rid, &routine, &type_registry);
                apply_access_pattern(&mut svc.diag_comm, &routine.access, &access_patterns);
                diag_services.push(svc);
            }
        }
    }

    // Generate services from the `services` section (TesterPresent, ControlDTCSetting, etc.)
    if let Some(yaml_services) = &doc.services {
        let svc_gen = crate::service_generator::ServiceGenerator::new(yaml_services)
            .with_sessions(doc.sessions.as_ref())
            .with_security(doc.security.as_ref());
        diag_services.extend(svc_gen.generate_all());
    }

    // Build ECU jobs from ecu_jobs section
    let mut single_ecu_jobs = Vec::new();
    if let Some(jobs) = &doc.ecu_jobs {
        for job in jobs.values() {
            single_ecu_jobs.push(ecu_job_to_ir(job, &type_registry));
        }
    }

    // Build SDGs from sdgs section, plus identification metadata
    let mut layer_sdg_vec: Vec<Sdg> = Vec::new();
    if let Some(sdg_map) = &doc.sdgs {
        let converted = convert_sdgs(sdg_map);
        layer_sdg_vec.extend(converted.sdgs);
    }
    if let Some(ident) = &doc.identification {
        if let Ok(ident_yaml) = serde_yaml::to_string(ident) {
            layer_sdg_vec.push(Sdg {
                caption_sn: "identification".into(),
                sds: vec![SdOrSdg::Sd(Sd {
                    value: ident_yaml,
                    si: String::new(),
                    ti: String::new(),
                })],
                si: String::new(),
            });
        }
    }
    if let Some(comparams) = &doc.comparams {
        if let Ok(cp_yaml) = serde_yaml::to_string(comparams) {
            layer_sdg_vec.push(Sdg {
                caption_sn: "comparams".into(),
                sds: vec![SdOrSdg::Sd(Sd {
                    value: cp_yaml,
                    si: String::new(),
                    ti: String::new(),
                })],
                si: String::new(),
            });
        }
    }
    if let Some(dtc_config) = &doc.dtc_config {
        if let Ok(dc_yaml) = serde_yaml::to_string(dtc_config) {
            layer_sdg_vec.push(Sdg {
                caption_sn: "dtc_config".into(),
                sds: vec![SdOrSdg::Sd(Sd {
                    value: dc_yaml,
                    si: String::new(),
                    ti: String::new(),
                })],
                si: String::new(),
            });
        }
    }
    if let Some(annotations) = &doc.annotations {
        let ann_json = canonical_json(annotations);
        layer_sdg_vec.push(Sdg {
            caption_sn: "yaml_annotations".into(),
            sds: vec![SdOrSdg::Sd(Sd {
                value: ann_json,
                si: String::new(),
                ti: String::new(),
            })],
            si: String::new(),
        });
    }
    if let Some(x_oem) = &doc.x_oem {
        let xoem_json = canonical_json(x_oem);
        layer_sdg_vec.push(Sdg {
            caption_sn: "yaml_x_oem".into(),
            sds: vec![SdOrSdg::Sd(Sd {
                value: xoem_json,
                si: String::new(),
                ti: String::new(),
            })],
            si: String::new(),
        });
    }
    let sdgs = if layer_sdg_vec.is_empty() {
        None
    } else {
        Some(Sdgs {
            sdgs: layer_sdg_vec,
        })
    };

    // Build DTCs
    let dtcs = if let Some(serde_yaml::Value::Mapping(dtc_map)) = &doc.dtcs {
        dtc_map
            .iter()
            .filter_map(|(key, val)| {
                let code = parse_hex_key(key);
                serde_yaml::from_value::<YamlDtc>(val.clone())
                    .ok()
                    .map(|dtc| convert_dtc(code, &dtc))
            })
            .collect()
    } else {
        vec![]
    };

    // Build state charts from sessions, state_model, and security
    let mut state_charts = Vec::new();
    if let Some(sessions) = &doc.sessions {
        state_charts.push(parse_sessions_to_state_chart(
            sessions,
            doc.state_model.as_ref(),
        ));
    }
    if let Some(security) = &doc.security {
        state_charts.push(parse_security_to_state_chart(security));
    }
    if let Some(auth) = &doc.authentication {
        if let Some(sc) = parse_authentication_to_state_chart(auth) {
            state_charts.push(sc);
        }
    }

    // Build functional classes from YAML
    let funct_classes: Vec<FunctClass> = doc
        .functional_classes
        .as_ref()
        .map(|classes| {
            classes
                .iter()
                .map(|name| FunctClass {
                    short_name: name.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    // Build com_param_refs from YAML comparams section
    let com_param_refs = parse_comparams(doc);

    let memory = doc.memory.as_ref().map(parse_memory_config);

    // Build additional variants from variants.definitions FIRST
    // (so we can reference diag_services before moving it into the main variant)
    let mut additional_variants = Vec::new();
    if let Some(yaml_variants) = &doc.variants {
        if let Some(definitions) = &yaml_variants.definitions {
            for (vname, vdef) in definitions {
                let ecu_variant = parse_variant_definition(
                    vname,
                    vdef,
                    &ecu_name,
                    doc.sessions.as_ref(),
                    doc.security.as_ref(),
                    &diag_services,
                );
                additional_variants.push(ecu_variant);
            }
        }
    }

    // Build the main variant containing all services
    let variant = Variant {
        diag_layer: DiagLayer {
            short_name: ecu_name.clone(),
            long_name: None,
            funct_classes,
            com_param_refs,
            diag_services,
            single_ecu_jobs,
            state_charts,
            additional_audiences: vec![],
            sdgs,
        },
        is_base_variant: true,
        variant_patterns: vec![],
        parent_refs: vec![],
    };

    // Combine main variant with additional variants
    let mut variants = vec![variant];
    variants.extend(additional_variants);

    Ok(DiagDatabase {
        version,
        ecu_name,
        revision,
        metadata,
        variants,
        functional_groups: vec![],
        dtcs,
        memory,
        type_definitions,
    })
}

/// Registry of named types for resolving type references in DIDs.
struct TypeRegistry {
    types: BTreeMap<String, YamlType>,
}

fn build_type_registry(types: Option<&BTreeMap<String, YamlType>>) -> TypeRegistry {
    TypeRegistry {
        types: types.cloned().unwrap_or_default(),
    }
}

/// Resolve a DID type which can be either a string reference or inline type definition.
/// Returns `(Option<YamlType>, Option<type_key_name>)`.
fn resolve_did_type(
    type_value: &serde_yaml::Value,
    registry: &TypeRegistry,
) -> (Option<YamlType>, Option<String>) {
    match type_value {
        serde_yaml::Value::String(name) => (registry.types.get(name).cloned(), Some(name.clone())),
        serde_yaml::Value::Mapping(_) => (serde_yaml::from_value(type_value.clone()).ok(), None),
        _ => (None, None),
    }
}

/// Derive a CDA-compatible DOP name from a YAML type definition.
/// Priority: explicit `dop_name` > identical type naming > fallback.
fn cda_dop_name_for_type(yaml_type: &YamlType, fallback: &str) -> String {
    if let Some(ref name) = yaml_type.dop_name {
        return name.clone();
    }
    let is_identical =
        yaml_type.entries.is_none() && yaml_type.scale.is_none() && yaml_type.offset.is_none();
    if is_identical {
        match yaml_type.base.as_str() {
            "u8" => return "IDENTICAL_UINT_8".into(),
            "u16" => return "IDENTICAL_UINT_16".into(),
            "u32" => {
                let bits = yaml_type.bit_length.unwrap_or(32);
                return format!("IDENTICAL_UINT_{bits}");
            }
            _ => {}
        }
    }
    fallback.to_string()
}

/// Convert a YAML type definition to IR DOP.
fn yaml_type_to_dop(name: &str, yaml_type: &YamlType) -> Dop {
    let (base_data_type, phys_data_type) = base_type_to_data_type(&yaml_type.base);

    let is_high_low = yaml_type.endian.as_deref().is_none_or(|e| e == "big");

    let bit_length = yaml_type
        .bit_length
        .or_else(|| yaml_type.length.map(|l| l * 8))
        .or_else(|| default_bit_length(&yaml_type.base));

    // Build CompuMethod from scale/offset or enum
    let compu_method = Some(build_compu_method(yaml_type));

    let diag_coded_type = DiagCodedType {
        type_name: if yaml_type.min_length.is_some() || yaml_type.max_length.is_some() {
            DiagCodedTypeName::MinMaxLengthType
        } else {
            DiagCodedTypeName::StandardLengthType
        },
        base_type_encoding: if yaml_type.base.starts_with('s') || yaml_type.base.starts_with('i') {
            "signed".into()
        } else {
            "unsigned".into()
        },
        base_data_type,
        is_high_low_byte_order: is_high_low,
        specific_data: if yaml_type.min_length.is_some() || yaml_type.max_length.is_some() {
            let termination = match yaml_type.termination.as_deref() {
                Some("zero") => Termination::Zero,
                Some("hex_ff") | Some("hexff") => Termination::HexFf,
                _ => Termination::EndOfPdu,
            };
            Some(DiagCodedTypeData::MinMax {
                min_length: yaml_type.min_length.unwrap_or(0),
                max_length: yaml_type.max_length,
                termination,
            })
        } else {
            bit_length.map(|bl| DiagCodedTypeData::StandardLength {
                bit_length: bl,
                bit_mask: vec![],
                condensed: false,
            })
        },
    };

    // Build unit if present
    let unit_ref = yaml_type.unit.as_ref().map(|u| Unit {
        short_name: u.clone(),
        display_name: u.clone(),
        factor_si_to_unit: None,
        offset_si_to_unit: None,
        physical_dimension: None,
    });

    // Build constraints
    let internal_constr = yaml_type
        .constraints
        .as_ref()
        .and_then(|c| c.internal.as_ref())
        .and_then(|vals| {
            if vals.len() == 2 {
                Some(InternalConstr {
                    lower_limit: Some(Limit {
                        value: yaml_value_to_string(&vals[0]),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: yaml_value_to_string(&vals[1]),
                        interval_type: IntervalType::Closed,
                    }),
                    scale_constrs: vec![],
                })
            } else {
                None
            }
        });

    Dop {
        dop_type: DopType::Regular,
        short_name: name.into(),
        sdgs: None,
        specific_data: Some(DopData::NormalDop {
            compu_method,
            diag_coded_type: Some(diag_coded_type),
            physical_type: Some(PhysicalType {
                precision: None,
                base_data_type: phys_data_type,
                display_radix: Radix::Dec,
            }),
            internal_constr,
            unit_ref,
            phys_constr: None,
        }),
    }
}

fn build_compu_method(yaml_type: &YamlType) -> CompuMethod {
    // Text table / enum
    if let Some(serde_yaml::Value::Mapping(enum_values)) = &yaml_type.enum_values {
        let scales: Vec<CompuScale> = enum_values
            .iter()
            .map(|(k, v)| {
                let v_str = yaml_value_to_string(v);
                CompuScale {
                    short_label: Some(Text {
                        value: v_str.clone(),
                        ti: String::new(),
                    }),
                    lower_limit: Some(Limit {
                        value: yaml_value_to_string(k),
                        interval_type: IntervalType::Closed,
                    }),
                    upper_limit: Some(Limit {
                        value: yaml_value_to_string(k),
                        interval_type: IntervalType::Closed,
                    }),
                    inverse_values: None,
                    consts: Some(CompuValues {
                        v: None,
                        vt: v_str,
                        vt_ti: String::new(),
                    }),
                    rational_co_effs: None,
                }
            })
            .collect();
        return CompuMethod {
            category: CompuCategory::TextTable,
            internal_to_phys: Some(CompuInternalToPhys {
                compu_scales: scales,
                prog_code: None,
                compu_default_value: None,
            }),
            phys_to_internal: None,
        };
    }

    // Linear scale/offset
    if yaml_type.scale.is_some() || yaml_type.offset.is_some() {
        let scale = yaml_type.scale.unwrap_or(1.0);
        let offset = yaml_type.offset.unwrap_or(0.0);
        return CompuMethod {
            category: CompuCategory::Linear,
            internal_to_phys: Some(CompuInternalToPhys {
                compu_scales: vec![CompuScale {
                    short_label: None,
                    lower_limit: None,
                    upper_limit: None,
                    inverse_values: None,
                    consts: None,
                    rational_co_effs: Some(CompuRationalCoEffs {
                        numerator: vec![offset, scale],
                        denominator: vec![1.0],
                    }),
                }],
                prog_code: None,
                compu_default_value: None,
            }),
            phys_to_internal: None,
        };
    }

    // Identical (no conversion)
    CompuMethod {
        category: CompuCategory::Identical,
        internal_to_phys: None,
        phys_to_internal: None,
    }
}

/// Create a ReadDataByIdentifier (0x22) service from a DID definition.
fn did_to_read_service(did_id: u32, did: &Did, registry: &TypeRegistry) -> DiagService {
    let (yaml_type, _type_key) = resolve_did_type(&did.did_type, registry);
    let dop_name = yaml_type
        .as_ref()
        .map_or_else(|| did.name.clone(), |t| cda_dop_name_for_type(t, &did.name));
    let data_param_name = did.param_name.as_deref().unwrap_or(&did.name);
    let dop = yaml_type.as_ref().map_or_else(
        || Dop {
            dop_type: DopType::Regular,
            short_name: dop_name.clone(),
            sdgs: None,
            specific_data: None,
        },
        |t| yaml_type_to_dop(&dop_name, t),
    );

    // Preserve DID-specific YAML fields in an SDG for roundtrip
    let mut did_extra = serde_json::Map::new();
    if let Some(snap) = did.snapshot {
        did_extra.insert("snapshot".into(), serde_json::Value::Bool(snap));
    }
    if let Some(ioc) = &did.io_control {
        let json_val = serde_json::to_value(ioc).unwrap_or_default();
        did_extra.insert("io_control".into(), json_val);
    }
    let did_sdgs = if did_extra.is_empty() {
        None
    } else {
        let json_str = serde_json::to_string(&did_extra).unwrap_or_default();
        Some(Sdgs {
            sdgs: vec![Sdg {
                caption_sn: "did_extra".into(),
                sds: vec![SdOrSdg::Sd(Sd {
                    value: json_str,
                    si: String::new(),
                    ti: String::new(),
                })],
                si: String::new(),
            }],
        })
    };

    DiagService {
        diag_comm: DiagComm {
            short_name: format!("{}_Read", did.name),
            long_name: None,
            semantic: String::new(),
            funct_classes: vec![FunctClass {
                short_name: "Ident".into(),
            }],
            sdgs: did_sdgs,
            diag_class_type: DiagClassType::StartComm,
            pre_condition_state_refs: vec![],
            state_transition_refs: vec![],
            protocols: vec![],
            audience: did.audience.as_ref().map(yaml_service_audience_to_ir),
            is_mandatory: false,
            is_executable: true,
            is_final: false,
        },
        request: Some(Request {
            params: vec![
                Param {
                    id: 0,
                    param_type: ParamType::CodedConst,
                    short_name: "SID_RQ".into(),
                    semantic: "SERVICE-ID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(0),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: "34".into(),
                        diag_coded_type: uint8_coded_type(),
                    }),
                },
                Param {
                    id: 1,
                    param_type: ParamType::CodedConst,
                    short_name: "DID_RQ".into(),
                    semantic: "DID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(1),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: format!("{did_id}"),
                        diag_coded_type: uint16_coded_type(),
                    }),
                },
            ],
            sdgs: None,
        }),
        pos_responses: vec![Response {
            response_type: ResponseType::PosResponse,
            params: vec![
                Param {
                    id: 0,
                    param_type: ParamType::CodedConst,
                    short_name: "SID_PR".into(),
                    semantic: "SERVICE-ID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(0),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: "98".into(),
                        diag_coded_type: uint8_coded_type(),
                    }),
                },
                Param {
                    id: 1,
                    param_type: ParamType::MatchingRequestParam,
                    short_name: "DID_PR".into(),
                    semantic: "DID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(1),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::MatchingRequestParam {
                        request_byte_pos: 1,
                        byte_length: 2,
                    }),
                },
                // Data value
                Param {
                    id: 2,
                    param_type: ParamType::Value,
                    short_name: data_param_name.to_string(),
                    semantic: "DATA".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(3),
                    bit_position: None,
                    specific_data: Some(ParamData::Value {
                        physical_default_value: String::new(),
                        dop: Box::new(dop),
                    }),
                },
            ],
            sdgs: None,
        }],
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    }
}

/// Create a WriteDataByIdentifier (0x2E) service from a DID definition.
fn did_to_write_service(did_id: u32, did: &Did, registry: &TypeRegistry) -> DiagService {
    let (yaml_type, _type_key) = resolve_did_type(&did.did_type, registry);
    let dop_name = yaml_type
        .as_ref()
        .map_or_else(|| did.name.clone(), |t| cda_dop_name_for_type(t, &did.name));
    let data_param_name = did.param_name.as_deref().unwrap_or(&did.name);
    let dop = yaml_type.as_ref().map_or_else(
        || Dop {
            dop_type: DopType::Regular,
            short_name: dop_name.clone(),
            sdgs: None,
            specific_data: None,
        },
        |t| yaml_type_to_dop(&dop_name, t),
    );

    DiagService {
        diag_comm: DiagComm {
            short_name: format!("{}_Write", did.name),
            long_name: None,
            semantic: String::new(),
            funct_classes: vec![FunctClass {
                short_name: "Ident".into(),
            }],
            sdgs: None,
            diag_class_type: DiagClassType::StartComm,
            pre_condition_state_refs: vec![],
            state_transition_refs: vec![],
            protocols: vec![],
            audience: did.audience.as_ref().map(yaml_service_audience_to_ir),
            is_mandatory: false,
            is_executable: true,
            is_final: false,
        },
        request: Some(Request {
            params: vec![
                Param {
                    id: 0,
                    param_type: ParamType::CodedConst,
                    short_name: "SID_RQ".into(),
                    semantic: "SERVICE-ID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(0),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: "46".into(),
                        diag_coded_type: uint8_coded_type(),
                    }),
                },
                Param {
                    id: 1,
                    param_type: ParamType::CodedConst,
                    short_name: "DID_RQ".into(),
                    semantic: "DID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(1),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: format!("{did_id}"),
                        diag_coded_type: uint16_coded_type(),
                    }),
                },
                Param {
                    id: 2,
                    param_type: ParamType::Value,
                    short_name: data_param_name.to_string(),
                    semantic: "DATA".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(3),
                    bit_position: None,
                    specific_data: Some(ParamData::Value {
                        physical_default_value: String::new(),
                        dop: Box::new(dop),
                    }),
                },
            ],
            sdgs: None,
        }),
        pos_responses: vec![Response {
            response_type: ResponseType::PosResponse,
            params: vec![
                Param {
                    id: 0,
                    param_type: ParamType::CodedConst,
                    short_name: "SID_PR".into(),
                    semantic: "SERVICE-ID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(0),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: "110".into(),
                        diag_coded_type: uint8_coded_type(),
                    }),
                },
                Param {
                    id: 1,
                    param_type: ParamType::MatchingRequestParam,
                    short_name: "DID_PR".into(),
                    semantic: "DID".into(),
                    sdgs: None,
                    physical_default_value: String::new(),
                    byte_position: Some(1),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::MatchingRequestParam {
                        request_byte_pos: 1,
                        byte_length: 2,
                    }),
                },
            ],
            sdgs: None,
        }],
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    }
}

/// Convert a routine definition to a RoutineControl (0x31) service.
fn routine_to_service(rid: u32, routine: &Routine, _registry: &TypeRegistry) -> DiagService {
    let mut request_params = vec![
        Param {
            id: 0,
            param_type: ParamType::CodedConst,
            short_name: "SID_RQ".into(),
            semantic: "SERVICE-ID".into(),
            sdgs: None,
            physical_default_value: String::new(),
            byte_position: Some(0),
            bit_position: Some(0),
            specific_data: Some(ParamData::CodedConst {
                coded_value: "49".into(),
                diag_coded_type: uint8_coded_type(),
            }),
        },
        Param {
            id: 1,
            param_type: ParamType::CodedConst,
            short_name: "RID_RQ".into(),
            semantic: "ID".into(),
            sdgs: None,
            physical_default_value: String::new(),
            byte_position: Some(2),
            bit_position: Some(0),
            specific_data: Some(ParamData::CodedConst {
                coded_value: format!("{rid}"),
                diag_coded_type: uint16_coded_type(),
            }),
        },
    ];

    // Add start input params if present
    if let Some(params) = &routine.parameters {
        if let Some(start) = params.get("start") {
            if let Some(inputs) = &start.input {
                let mut id = 2u32;
                for input in inputs {
                    let yaml_type: Option<YamlType> =
                        serde_yaml::from_value(input.param_type.clone()).ok();
                    let dop = yaml_type.as_ref().map_or_else(
                        || Dop {
                            dop_type: DopType::Regular,
                            short_name: input.name.clone(),
                            sdgs: None,
                            specific_data: None,
                        },
                        |t| yaml_type_to_dop(&input.name, t),
                    );
                    request_params.push(Param {
                        id,
                        param_type: ParamType::Value,
                        short_name: input.name.clone(),
                        semantic: input.semantic.clone().unwrap_or_else(|| "DATA".into()),
                        sdgs: None,
                        physical_default_value: String::new(),
                        byte_position: None,
                        bit_position: None,
                        specific_data: Some(ParamData::Value {
                            physical_default_value: String::new(),
                            dop: Box::new(dop),
                        }),
                    });
                    id += 1;
                }
            }
        }
    }

    // Build positive response from result output params
    let mut pos_responses = Vec::new();
    if let Some(params) = &routine.parameters {
        if let Some(result) = params.get("result") {
            if let Some(outputs) = &result.output {
                let mut resp_params = Vec::new();
                for (id, output) in outputs.iter().enumerate() {
                    let yaml_type: Option<YamlType> =
                        serde_yaml::from_value(output.param_type.clone()).ok();
                    let dop = yaml_type.as_ref().map_or_else(
                        || Dop {
                            dop_type: DopType::Regular,
                            short_name: output.name.clone(),
                            sdgs: None,
                            specific_data: None,
                        },
                        |t| yaml_type_to_dop(&output.name, t),
                    );
                    let id = id as u32;
                    resp_params.push(Param {
                        id,
                        param_type: ParamType::Value,
                        short_name: output.name.clone(),
                        semantic: "DATA".into(),
                        sdgs: None,
                        physical_default_value: String::new(),
                        byte_position: None,
                        bit_position: None,
                        specific_data: Some(ParamData::Value {
                            physical_default_value: String::new(),
                            dop: Box::new(dop),
                        }),
                    });
                }
                if !resp_params.is_empty() {
                    pos_responses.push(Response {
                        response_type: ResponseType::PosResponse,
                        params: resp_params,
                        sdgs: None,
                    });
                }
            }
        }
    }

    DiagService {
        diag_comm: DiagComm {
            short_name: routine.name.clone(),
            long_name: routine.description.as_ref().map(|d| LongName {
                value: d.clone(),
                ti: String::new(),
            }),
            semantic: String::new(),
            funct_classes: vec![],
            sdgs: None,
            diag_class_type: DiagClassType::StartComm,
            pre_condition_state_refs: vec![],
            state_transition_refs: vec![],
            protocols: vec![],
            audience: routine.audience.as_ref().map(yaml_service_audience_to_ir),
            is_mandatory: false,
            is_executable: true,
            is_final: false,
        },
        request: Some(Request {
            params: request_params,
            sdgs: None,
        }),
        pos_responses,
        neg_responses: vec![],
        is_cyclic: false,
        is_multiple: false,
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        com_param_refs: vec![],
    }
}

/// Convert an ECU job definition to IR SingleEcuJob.
fn ecu_job_to_ir(job: &EcuJob, _registry: &TypeRegistry) -> SingleEcuJob {
    let convert_job_params = |params: &Option<Vec<JobParamDef>>| -> Vec<JobParam> {
        params
            .as_ref()
            .map(|ps| {
                ps.iter()
                    .map(|p| {
                        let yaml_type: Option<YamlType> =
                            serde_yaml::from_value(p.param_type.clone()).ok();
                        let dop_base = yaml_type
                            .as_ref()
                            .map(|t| Box::new(yaml_type_to_dop(&p.name, t)));
                        JobParam {
                            short_name: p.name.clone(),
                            long_name: p.description.as_ref().map(|d| LongName {
                                value: d.clone(),
                                ti: String::new(),
                            }),
                            physical_default_value: p
                                .default_value
                                .as_ref()
                                .map(yaml_value_to_string)
                                .unwrap_or_default(),
                            dop_base,
                            semantic: p.semantic.clone().unwrap_or_default(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    SingleEcuJob {
        diag_comm: DiagComm {
            short_name: job.name.clone(),
            long_name: job.description.as_ref().map(|d| LongName {
                value: d.clone(),
                ti: String::new(),
            }),
            semantic: "ECU-JOB".into(),
            funct_classes: vec![],
            sdgs: None,
            diag_class_type: DiagClassType::StartComm,
            pre_condition_state_refs: vec![],
            state_transition_refs: vec![],
            protocols: vec![],
            audience: job.audience.as_ref().map(yaml_service_audience_to_ir),
            is_mandatory: false,
            is_executable: true,
            is_final: false,
        },
        prog_codes: job
            .prog_code
            .as_ref()
            .map(|pc| {
                vec![ProgCode {
                    code_file: pc.clone(),
                    encryption: String::new(),
                    syntax: String::new(),
                    revision: String::new(),
                    entrypoint: String::new(),
                    libraries: vec![],
                }]
            })
            .unwrap_or_default(),
        input_params: convert_job_params(&job.input_params),
        output_params: convert_job_params(&job.output_params),
        neg_output_params: convert_job_params(&job.neg_output_params),
    }
}

/// Convert YAML SDGs to IR SDGs.
fn convert_sdgs(sdg_map: &BTreeMap<String, YamlSdg>) -> Sdgs {
    Sdgs {
        sdgs: sdg_map.values().map(convert_single_sdg).collect(),
    }
}

fn convert_single_sdg(yaml_sdg: &YamlSdg) -> Sdg {
    let sds = yaml_sdg
        .values
        .iter()
        .map(|v| {
            if v.values.is_some() {
                // Nested SDG
                let nested = YamlSdg {
                    si: v.si.clone(),
                    caption: v.caption.clone().unwrap_or_default(),
                    values: v.values.clone().unwrap_or_default(),
                };
                SdOrSdg::Sdg(convert_single_sdg(&nested))
            } else {
                SdOrSdg::Sd(Sd {
                    value: v.value.clone().unwrap_or_default(),
                    si: v.si.clone(),
                    ti: v.ti.clone().unwrap_or_default(),
                })
            }
        })
        .collect();

    Sdg {
        caption_sn: yaml_sdg.caption.clone(),
        sds,
        si: yaml_sdg.si.clone(),
    }
}

/// Convert a YAML DTC to IR DTC.
fn convert_dtc(trouble_code: u32, yaml_dtc: &YamlDtc) -> Dtc {
    // Store snapshot and extended_data references in SDGs for roundtrip
    let mut sdg_entries = Vec::new();
    if let Some(snaps) = &yaml_dtc.snapshots {
        if !snaps.is_empty() {
            sdg_entries.push(Sdg {
                caption_sn: "dtc_snapshots".into(),
                sds: snaps
                    .iter()
                    .map(|s| {
                        SdOrSdg::Sd(Sd {
                            value: s.clone(),
                            si: String::new(),
                            ti: String::new(),
                        })
                    })
                    .collect(),
                si: String::new(),
            });
        }
    }
    if let Some(ext) = &yaml_dtc.extended_data {
        if !ext.is_empty() {
            sdg_entries.push(Sdg {
                caption_sn: "dtc_extended_data".into(),
                sds: ext
                    .iter()
                    .map(|s| {
                        SdOrSdg::Sd(Sd {
                            value: s.clone(),
                            si: String::new(),
                            ti: String::new(),
                        })
                    })
                    .collect(),
                si: String::new(),
            });
        }
    }

    Dtc {
        short_name: yaml_dtc.name.clone(),
        trouble_code,
        display_trouble_code: yaml_dtc.sae.clone(),
        text: yaml_dtc.description.as_ref().map(|d| Text {
            value: d.clone(),
            ti: String::new(),
        }),
        level: yaml_dtc.severity,
        sdgs: if sdg_entries.is_empty() {
            None
        } else {
            Some(Sdgs { sdgs: sdg_entries })
        },
        is_temporary: false,
    }
}

// --- Helpers ---

fn parse_hex_key(key: &serde_yaml::Value) -> u32 {
    match key {
        serde_yaml::Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
        serde_yaml::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                s.parse::<u32>().unwrap_or(0)
            }
        }
        _ => 0,
    }
}

fn yaml_value_to_string(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => format!("{v:?}"),
    }
}

fn base_type_to_data_type(base: &str) -> (DataType, PhysicalTypeDataType) {
    match base {
        "u8" | "s8" => (DataType::AUint32, PhysicalTypeDataType::AUint32),
        "u16" | "s16" => (DataType::AUint32, PhysicalTypeDataType::AUint32),
        "u32" | "s32" | "u64" | "s64" => (DataType::AUint32, PhysicalTypeDataType::AUint32),
        "f32" => (DataType::AFloat32, PhysicalTypeDataType::AFloat32),
        "f64" => (DataType::AFloat64, PhysicalTypeDataType::AFloat64),
        "ascii" => (DataType::AAsciiString, PhysicalTypeDataType::AAsciiString),
        "utf8" => (DataType::AUtf8String, PhysicalTypeDataType::AAsciiString),
        "unicode" => (
            DataType::AUnicode2String,
            PhysicalTypeDataType::AAsciiString,
        ),
        "bytes" => (DataType::ABytefield, PhysicalTypeDataType::ABytefield),
        "struct" => (DataType::ABytefield, PhysicalTypeDataType::ABytefield),
        _ => (DataType::AUint32, PhysicalTypeDataType::AUint32),
    }
}

fn default_bit_length(base: &str) -> Option<u32> {
    match base {
        "u8" | "s8" => Some(8),
        "u16" | "s16" => Some(16),
        "u32" | "s32" | "f32" => Some(32),
        "u64" | "s64" | "f64" => Some(64),
        _ => None,
    }
}

fn uint8_coded_type() -> DiagCodedType {
    DiagCodedType {
        type_name: DiagCodedTypeName::StandardLengthType,
        base_type_encoding: "unsigned".into(),
        base_data_type: DataType::AUint32,
        is_high_low_byte_order: true,
        specific_data: Some(DiagCodedTypeData::StandardLength {
            bit_length: 8,
            bit_mask: vec![],
            condensed: false,
        }),
    }
}

fn uint16_coded_type() -> DiagCodedType {
    DiagCodedType {
        type_name: DiagCodedTypeName::StandardLengthType,
        base_type_encoding: "unsigned".into(),
        base_data_type: DataType::AUint32,
        is_high_low_byte_order: true,
        specific_data: Some(DiagCodedTypeData::StandardLength {
            bit_length: 16,
            bit_mask: vec![],
            condensed: false,
        }),
    }
}

// --- Memory config ---

fn parse_memory_config(mc: &YamlMemoryConfig) -> MemoryConfig {
    let default_address_format = mc
        .default_address_format
        .as_ref()
        .map(|af| AddressFormat {
            address_bytes: af.address_bytes,
            length_bytes: af.length_bytes,
        })
        .unwrap_or_default();

    let regions = mc
        .regions
        .as_ref()
        .map(|regs| {
            regs.values()
                .map(|r| {
                    let session = r.session.as_ref().and_then(|s| match s {
                        serde_yaml::Value::String(s) => Some(vec![s.clone()]),
                        serde_yaml::Value::Sequence(seq) => Some(
                            seq.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect(),
                        ),
                        _ => None,
                    });
                    MemoryRegion {
                        name: r.name.clone(),
                        description: r.description.clone(),
                        start_address: r.start,
                        size: r.end.saturating_sub(r.start),
                        access: match r.access.as_str() {
                            "write" => MemoryAccess::Write,
                            "read_write" => MemoryAccess::ReadWrite,
                            "execute" => MemoryAccess::Execute,
                            _ => MemoryAccess::Read,
                        },
                        address_format: r.address_format.as_ref().map(|af| AddressFormat {
                            address_bytes: af.address_bytes,
                            length_bytes: af.length_bytes,
                        }),
                        security_level: r.security_level.clone(),
                        session,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let data_blocks = mc
        .data_blocks
        .as_ref()
        .map(|blocks| {
            blocks
                .values()
                .map(|b| DataBlock {
                    name: b.name.clone(),
                    description: b.description.clone(),
                    block_type: match b.block_type.as_str() {
                        "upload" => DataBlockType::Upload,
                        _ => DataBlockType::Download,
                    },
                    memory_address: b.memory_address,
                    memory_size: b.memory_size,
                    format: match b.format.as_str() {
                        "encrypted" => DataBlockFormat::Encrypted,
                        "compressed" => DataBlockFormat::Compressed,
                        "encrypted_compressed" => DataBlockFormat::EncryptedCompressed,
                        _ => DataBlockFormat::Raw,
                    },
                    max_block_length: b.max_block_length,
                    security_level: b.security_level.clone(),
                    session: b.session.clone(),
                    checksum_type: b.checksum_type.clone(),
                })
                .collect()
        })
        .unwrap_or_default();

    MemoryConfig {
        default_address_format,
        regions,
        data_blocks,
    }
}

// --- Sessions and security -> state chart ---

fn yaml_value_to_u64(v: &serde_yaml::Value) -> u64 {
    match v {
        serde_yaml::Value::Number(n) => n.as_u64().unwrap_or(0),
        serde_yaml::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).unwrap_or(0)
            } else {
                s.parse().unwrap_or(0)
            }
        }
        _ => 0,
    }
}

fn parse_sessions_to_state_chart(
    sessions: &BTreeMap<String, Session>,
    state_model: Option<&StateModel>,
) -> StateChart {
    // Build mapping from YAML key to CDA-compatible state name (alias or capitalized key)
    let key_to_cda: BTreeMap<&str, String> = sessions
        .iter()
        .map(|(key, session)| {
            let cda_name = session
                .alias
                .clone()
                .unwrap_or_else(|| capitalize_first(key));
            (key.as_str(), cda_name)
        })
        .collect();

    let states: Vec<State> = sessions
        .iter()
        .map(|(key, session)| {
            let id = yaml_value_to_u64(&session.id);
            let cda_name = key_to_cda
                .get(key.as_str())
                .cloned()
                .unwrap_or_else(|| key.clone());
            State {
                short_name: cda_name,
                long_name: Some(LongName {
                    value: id.to_string(),
                    ti: key.clone(), // Store YAML key for roundtrip
                }),
            }
        })
        .collect();

    // Determine start state - map YAML key to CDA name
    let yaml_start = state_model
        .and_then(|sm| sm.initial_state.as_ref())
        .map_or("default", |is| is.session.as_str());
    let start_state = key_to_cda
        .get(yaml_start)
        .cloned()
        .unwrap_or_else(|| capitalize_first(yaml_start));

    // Build transitions - map YAML keys to CDA names
    let state_transitions: Vec<StateTransition> = state_model
        .and_then(|sm| sm.session_transitions.as_ref())
        .map(|transitions| {
            let mut result = Vec::new();
            for (from, targets) in transitions {
                let cda_from = key_to_cda
                    .get(from.as_str())
                    .cloned()
                    .unwrap_or_else(|| from.clone());
                for to in targets {
                    let cda_to = key_to_cda
                        .get(to.as_str())
                        .cloned()
                        .unwrap_or_else(|| to.clone());
                    result.push(StateTransition {
                        short_name: format!("{cda_from}_to_{cda_to}"),
                        source_short_name_ref: cda_from.clone(),
                        target_short_name_ref: cda_to.clone(),
                    });
                }
            }
            result
        })
        .unwrap_or_default();

    StateChart {
        short_name: "Session".into(),
        semantic: String::new(),
        state_transitions,
        start_state_short_name_ref: start_state,
        states,
    }
}

pub(crate) fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn parse_security_to_state_chart(security: &BTreeMap<String, SecurityLevel>) -> StateChart {
    // Locked state (start state, always present)
    let mut states = vec![State {
        short_name: "Locked".into(),
        long_name: Some(LongName {
            value: "0".into(),
            ti: String::new(),
        }),
    }];

    // Build mapping from YAML key to CDA name (Level_N)
    let key_to_cda: BTreeMap<&str, String> = security
        .iter()
        .map(|(key, level)| (key.as_str(), format!("Level_{}", level.level)))
        .collect();

    for (key, level) in security {
        let cda_name = key_to_cda
            .get(key.as_str())
            .cloned()
            .unwrap_or_else(|| key.clone());
        states.push(State {
            short_name: cda_name,
            long_name: Some(LongName {
                value: level.level.to_string(),
                ti: key.clone(), // Store YAML key for roundtrip
            }),
        });
    }

    // Build transitions: Locked->Locked (self), Locked->Level_N, Level_N->Locked
    let mut transitions = vec![StateTransition {
        short_name: "Locked_to_Locked".into(),
        source_short_name_ref: "Locked".into(),
        target_short_name_ref: "Locked".into(),
    }];
    for key in security.keys() {
        let cda_name = key_to_cda
            .get(key.as_str())
            .cloned()
            .unwrap_or_else(|| key.clone());
        transitions.push(StateTransition {
            short_name: format!("Locked_to_{cda_name}"),
            source_short_name_ref: "Locked".into(),
            target_short_name_ref: cda_name.clone(),
        });
    }
    for key in security.keys() {
        let cda_name = key_to_cda
            .get(key.as_str())
            .cloned()
            .unwrap_or_else(|| key.clone());
        transitions.push(StateTransition {
            short_name: format!("{cda_name}_to_Locked"),
            source_short_name_ref: cda_name,
            target_short_name_ref: "Locked".into(),
        });
    }

    StateChart {
        short_name: "SecurityAccess".into(),
        semantic: String::new(),
        state_transitions: transitions,
        start_state_short_name_ref: "Locked".into(),
        states,
    }
}

fn parse_authentication_to_state_chart(auth: &Authentication) -> Option<StateChart> {
    let roles = auth.roles.as_ref()?;
    if roles.is_empty() {
        return None;
    }
    let states: Vec<State> = roles
        .iter()
        .map(|(key, role_val)| {
            let id = role_val.get("id").map_or(0, yaml_value_to_u64);
            State {
                short_name: key.clone(),
                long_name: Some(LongName {
                    value: id.to_string(),
                    ti: String::new(),
                }),
            }
        })
        .collect();

    Some(StateChart {
        short_name: "Authentication".into(),
        semantic: String::new(),
        state_transitions: vec![],
        start_state_short_name_ref: String::new(),
        states,
    })
}

fn parse_variant_definition(
    name: &str,
    vdef: &VariantDef,
    base_variant_name: &str,
    sessions: Option<&BTreeMap<String, Session>>,
    security: Option<&BTreeMap<String, SecurityLevel>>,
    base_services: &[DiagService],
) -> Variant {
    // Build matching parameters from detect section
    let variant_patterns = if let Some(detect) = &vdef.detect {
        let mp = parse_detect_to_matching_parameter(detect, base_services);
        if let Some(mp) = mp {
            vec![VariantPattern {
                matching_parameters: vec![mp],
            }]
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    // Generate variant-specific services from overrides
    let diag_services = if let Some(yaml_services) = vdef.override_services() {
        let svc_gen = crate::service_generator::ServiceGenerator::new(&yaml_services)
            .with_sessions(sessions)
            .with_security(security);
        svc_gen.generate_all()
    } else {
        vec![]
    };

    Variant {
        diag_layer: DiagLayer {
            short_name: format!("{base_variant_name}_{name}"),
            long_name: None,
            funct_classes: vec![],
            com_param_refs: vec![],
            diag_services,
            single_ecu_jobs: vec![],
            state_charts: vec![],
            additional_audiences: vec![],
            sdgs: None,
        },
        is_base_variant: false,
        variant_patterns,
        parent_refs: vec![ParentRef {
            ref_type: ParentRefType::Variant(Box::new(Variant {
                diag_layer: DiagLayer {
                    short_name: base_variant_name.to_string(),
                    ..Default::default()
                },
                is_base_variant: true,
                variant_patterns: vec![],
                parent_refs: vec![],
            })),
            not_inherited_diag_comm_short_names: vec![],
            not_inherited_variables_short_names: vec![],
            not_inherited_dops_short_names: vec![],
            not_inherited_tables_short_names: vec![],
            not_inherited_global_neg_responses_short_names: vec![],
        }],
    }
}

/// Build a lookup from access pattern name -> Vec<PreConditionStateRef>.
fn build_access_pattern_lookup(
    patterns: Option<&BTreeMap<String, AccessPattern>>,
    sessions: Option<&BTreeMap<String, Session>>,
    security: Option<&BTreeMap<String, SecurityLevel>>,
    auth: Option<&Authentication>,
) -> HashMap<String, Vec<PreConditionStateRef>> {
    let patterns = match patterns {
        Some(p) => p,
        None => return HashMap::new(),
    };

    let session_states: HashMap<&str, State> = sessions
        .into_iter()
        .flat_map(|s| s.iter())
        .map(|(name, session)| {
            let id = yaml_value_to_u64(&session.id);
            let cda_name = session
                .alias
                .clone()
                .unwrap_or_else(|| capitalize_first(name));
            (
                name.as_str(),
                State {
                    short_name: cda_name,
                    long_name: Some(LongName {
                        value: id.to_string(),
                        ti: name.clone(),
                    }),
                },
            )
        })
        .collect();

    let security_states: HashMap<&str, State> = security
        .into_iter()
        .flat_map(|s| s.iter())
        .map(|(name, level)| {
            let cda_name = format!("Level_{}", level.level);
            (
                name.as_str(),
                State {
                    short_name: cda_name,
                    long_name: Some(LongName {
                        value: level.level.to_string(),
                        ti: name.clone(),
                    }),
                },
            )
        })
        .collect();

    let auth_states: HashMap<&str, State> = auth
        .and_then(|a| a.roles.as_ref())
        .into_iter()
        .flat_map(|roles| roles.iter())
        .map(|(name, role_val)| {
            let id = role_val.get("id").map_or(0, yaml_value_to_u64);
            (
                name.as_str(),
                State {
                    short_name: name.clone(),
                    long_name: Some(LongName {
                        value: id.to_string(),
                        ti: String::new(),
                    }),
                },
            )
        })
        .collect();

    patterns
        .iter()
        .map(|(pattern_name, pattern)| {
            let mut refs = Vec::new();

            // Session refs
            match &pattern.sessions {
                serde_yaml::Value::String(s) if s == "any" || s == "none" => {}
                serde_yaml::Value::Sequence(seq) => {
                    for item in seq {
                        if let Some(name) = item.as_str() {
                            if let Some(state) = session_states.get(name) {
                                refs.push(PreConditionStateRef {
                                    value: "Session".into(),
                                    in_param_if_short_name: String::new(),
                                    in_param_path_short_name: state.short_name.clone(),
                                    state: Some(state.clone()),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }

            // Security refs
            match &pattern.security {
                serde_yaml::Value::String(s) if s == "none" => {}
                serde_yaml::Value::Sequence(seq) => {
                    for item in seq {
                        if let Some(name) = item.as_str() {
                            if let Some(state) = security_states.get(name) {
                                refs.push(PreConditionStateRef {
                                    value: "SecurityAccess".into(),
                                    in_param_if_short_name: String::new(),
                                    in_param_path_short_name: state.short_name.clone(),
                                    state: Some(state.clone()),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }

            // Authentication refs
            match &pattern.authentication {
                serde_yaml::Value::String(s) if s == "none" => {}
                serde_yaml::Value::Sequence(seq) => {
                    for item in seq {
                        if let Some(name) = item.as_str() {
                            if let Some(state) = auth_states.get(name) {
                                refs.push(PreConditionStateRef {
                                    value: "Authentication".into(),
                                    in_param_if_short_name: String::new(),
                                    in_param_path_short_name: name.to_string(),
                                    state: Some(state.clone()),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }

            (pattern_name.clone(), refs)
        })
        .collect()
}

/// Look up access pattern for a service and attach pre-condition state refs + SDG metadata.
fn apply_access_pattern(
    diag_comm: &mut DiagComm,
    pattern_name: &str,
    patterns: &HashMap<String, Vec<PreConditionStateRef>>,
) {
    if pattern_name.is_empty() {
        return;
    }
    if let Some(refs) = patterns.get(pattern_name) {
        diag_comm.pre_condition_state_refs.clone_from(refs);
        // Store the pattern name in SDGs so the writer can reconstruct it
        let sdg = Sdg {
            caption_sn: "access_pattern".into(),
            sds: vec![SdOrSdg::Sd(Sd {
                value: pattern_name.to_string(),
                si: String::new(),
                ti: String::new(),
            })],
            si: String::new(),
        };
        match &mut diag_comm.sdgs {
            Some(sdgs) => sdgs.sdgs.push(sdg),
            None => diag_comm.sdgs = Some(Sdgs { sdgs: vec![sdg] }),
        }
    }
}

fn parse_detect_to_matching_parameter(
    detect: &serde_yaml::Value,
    base_services: &[DiagService],
) -> Option<MatchingParameter> {
    let rpm = detect.get("response_param_match")?;
    let service_name = rpm.get("service")?.as_str()?;
    let param_path = rpm.get("param_path")?.as_str()?;
    let expected = rpm.get("expected_value")?;
    let expected_str = match expected {
        serde_yaml::Value::Number(n) => format!("0x{:X}", n.as_u64().unwrap_or(0)),
        serde_yaml::Value::String(s) => s.clone(),
        _ => format!("{expected:?}"),
    };

    // Look up the actual service from the base services list
    let diag_service = base_services
        .iter()
        .find(|svc| svc.diag_comm.short_name == service_name)
        .cloned()
        .unwrap_or_else(|| {
            // Fallback to stub if service not found
            DiagService {
                diag_comm: DiagComm {
                    short_name: service_name.to_string(),
                    ..Default::default()
                },
                ..Default::default()
            }
        });

    // Find the output parameter in the service's positive response
    let out_param = diag_service
        .pos_responses
        .first()
        .and_then(|resp| {
            resp.params
                .iter()
                .find(|p| p.short_name == param_path)
                .cloned()
        })
        .unwrap_or_else(|| Param {
            short_name: param_path.to_string(),
            ..Default::default()
        });

    Some(MatchingParameter {
        expected_value: expected_str,
        diag_service: Box::new(diag_service),
        out_param: Box::new(out_param),
        use_physical_addressing: None,
    })
}

/// Create a DOP for a comparam from an explicit YAML definition.
fn make_comparam_dop(dop_def: Option<&ComParamDopDef>) -> Option<Dop> {
    let def = dop_def?;

    let base = def.base_type.as_deref()?;
    let bits = def
        .bit_length
        .unwrap_or_else(|| default_bit_length(base).unwrap_or(32));

    let internal_constr = if def.min.is_some() || def.max.is_some() {
        Some(InternalConstr {
            lower_limit: def.min.map(|v| Limit {
                value: v.to_string(),
                interval_type: IntervalType::Closed,
            }),
            upper_limit: def.max.map(|v| Limit {
                value: v.to_string(),
                interval_type: IntervalType::Closed,
            }),
            scale_constrs: vec![],
        })
    } else {
        None
    };

    let name = def.name.clone().unwrap_or_else(|| {
        let type_part = match base {
            "u8" | "u16" | "u32" | "u64" => "A_UINT32",
            "s8" | "s16" | "s32" | "s64" => "A_INT32",
            "f32" | "f64" => "A_FLOAT64",
            "string" | "ascii" | "utf8" => "A_ASCIISTRING",
            "bytes" => "A_BYTEFIELD",
            _ => "A_UINT32",
        };
        match (&def.min, &def.max) {
            (Some(min), Some(max)) => {
                let min_str = min.to_string().replace('-', "NEG").replace('.', "_");
                let max_str = max.to_string().replace('-', "NEG").replace('.', "_");
                format!("IDENTICAL_{type_part}_CONSTR_{min_str}_{max_str}")
            }
            (Some(min), None) => {
                let min_str = min.to_string().replace('-', "NEG").replace('.', "_");
                format!("IDENTICAL_{type_part}_CONSTR_{min_str}_INF")
            }
            (None, Some(max)) => {
                let max_str = max.to_string().replace('-', "NEG").replace('.', "_");
                format!("IDENTICAL_{type_part}_CONSTR_NEGINF_{max_str}")
            }
            (None, None) => format!("IDENTICAL_{type_part}"),
        }
    });

    let (data_type, _) = base_type_to_data_type(base);

    Some(Dop {
        dop_type: DopType::Regular,
        short_name: name,
        sdgs: None,
        specific_data: Some(DopData::NormalDop {
            compu_method: Some(CompuMethod {
                category: CompuCategory::Identical,
                internal_to_phys: None,
                phys_to_internal: None,
            }),
            diag_coded_type: Some(DiagCodedType {
                type_name: DiagCodedTypeName::StandardLengthType,
                base_type_encoding: String::new(),
                base_data_type: data_type,
                is_high_low_byte_order: true,
                specific_data: Some(DiagCodedTypeData::StandardLength {
                    bit_length: bits,
                    bit_mask: vec![],
                    condensed: false,
                }),
            }),
            physical_type: None,
            internal_constr,
            unit_ref: None,
            phys_constr: None,
        }),
    })
}

/// Parse usage string to ComParamUsage enum.
fn parse_comparam_usage(usage: Option<&str>) -> ComParamUsage {
    match usage.map(str::to_ascii_lowercase).as_deref() {
        Some("tester") => ComParamUsage::Tester,
        Some("ecu_software") | Some("ecusoftware") => ComParamUsage::EcuSoftware,
        Some("application") => ComParamUsage::Application,
        _ => ComParamUsage::EcuComm,
    }
}

/// Build child ComParams from YAML children definitions for complex comparams.
fn build_complex_comparam_children(
    yaml_children: Option<&[ComParamChild]>,
    values: Option<&[String]>,
) -> Vec<ComParam> {
    let Some(children) = yaml_children else {
        return vec![];
    };

    children
        .iter()
        .enumerate()
        .map(|(idx, child)| {
            let value = values.and_then(|v| v.get(idx)).cloned().unwrap_or_default();
            ComParam {
                com_param_type: ComParamType::Regular,
                short_name: child.name.clone(),
                long_name: None,
                param_class: child.param_class.clone().unwrap_or_default(),
                cp_type: ComParamStandardisationLevel::Standard,
                display_level: None,
                cp_usage: ComParamUsage::EcuComm,
                specific_data: Some(ComParamSpecificData::Regular {
                    physical_default_value: value,
                    dop: make_comparam_dop(child.dop.as_ref()).map(Box::new),
                }),
            }
        })
        .collect()
}

/// Parse YAML `comparams` section into IR `ComParamRef` entries.
///
/// Flat per-parameter format:
/// - Short form (scalar): `PARAM_NAME: value` -> one ComParamRef without protocol
/// - Full form: `PARAM_NAME: { values: { proto: val } }` -> one ComParamRef per protocol
/// - Full form with default only: `PARAM_NAME: { default: val }` -> one ComParamRef without protocol
fn parse_comparams(doc: &YamlDocument) -> Vec<ComParamRef> {
    let comparams = match &doc.comparams {
        Some(c) => c,
        None => return vec![],
    };

    let mut refs = Vec::new();
    for (param_name, entry) in comparams {
        match entry {
            ComParamEntry::Simple(val) => {
                let value_str = yaml_value_to_string(val);
                refs.push(ComParamRef {
                    simple_value: Some(SimpleValue {
                        value: value_str.clone(),
                    }),
                    complex_value: None,
                    com_param: Some(Box::new(ComParam {
                        com_param_type: ComParamType::Regular,
                        short_name: param_name.clone(),
                        long_name: None,
                        param_class: String::new(),
                        cp_type: ComParamStandardisationLevel::Standard,
                        display_level: None,
                        cp_usage: ComParamUsage::EcuComm,
                        specific_data: Some(ComParamSpecificData::Regular {
                            physical_default_value: value_str,
                            dop: None,
                        }),
                    })),
                    protocol: None,
                    prot_stack: None,
                });
            }
            ComParamEntry::Full(full) => {
                let is_complex = full
                    .cptype
                    .as_ref()
                    .is_some_and(super::yaml_model::ComParamTypeYaml::is_complex);

                if let Some(values) = &full.values {
                    for (proto_name, val) in values {
                        let (simple_value, complex_value) = parse_comparam_value(val);

                        let protocol = Protocol {
                            diag_layer: DiagLayer {
                                short_name: proto_name.clone(),
                                ..Default::default()
                            },
                            com_param_spec: None,
                            prot_stack: None,
                            parent_refs: vec![],
                        };

                        let (com_param_type, specific_data) = if is_complex {
                            let child_values: Option<Vec<String>> =
                                complex_value.as_ref().map(|cv| {
                                    cv.entries
                                        .iter()
                                        .filter_map(|e| match e {
                                            SimpleOrComplexValue::Simple(sv) => {
                                                Some(sv.value.clone())
                                            }
                                            SimpleOrComplexValue::Complex(_) => None,
                                        })
                                        .collect()
                                });
                            (
                                ComParamType::Complex,
                                Some(ComParamSpecificData::Complex {
                                    com_params: build_complex_comparam_children(
                                        full.children.as_deref(),
                                        child_values.as_deref(),
                                    ),
                                    complex_physical_default_values: complex_value
                                        .clone()
                                        .map(|cv| vec![cv])
                                        .unwrap_or_default(),
                                    allow_multiple_values: true,
                                }),
                            )
                        } else {
                            let physical_default_value = simple_value
                                .as_ref()
                                .map(|sv| sv.value.clone())
                                .unwrap_or_default();
                            (
                                ComParamType::Regular,
                                Some(ComParamSpecificData::Regular {
                                    physical_default_value,
                                    dop: make_comparam_dop(full.dop.as_ref()).map(Box::new),
                                }),
                            )
                        };

                        refs.push(ComParamRef {
                            simple_value,
                            complex_value,
                            com_param: Some(Box::new(ComParam {
                                com_param_type,
                                short_name: param_name.clone(),
                                long_name: None,
                                param_class: full.param_class.clone().unwrap_or_default(),
                                cp_type: ComParamStandardisationLevel::Standard,
                                display_level: None,
                                cp_usage: parse_comparam_usage(full.usage.as_deref()),
                                specific_data,
                            })),
                            protocol: Some(Box::new(protocol)),
                            prot_stack: None,
                        });
                    }
                } else if let Some(default_val) = &full.default {
                    let value_str = yaml_value_to_string(default_val);

                    let (com_param_type, specific_data) = if is_complex {
                        (
                            ComParamType::Complex,
                            Some(ComParamSpecificData::Complex {
                                com_params: build_complex_comparam_children(
                                    full.children.as_deref(),
                                    None,
                                ),
                                complex_physical_default_values: vec![],
                                allow_multiple_values: true,
                            }),
                        )
                    } else {
                        (
                            ComParamType::Regular,
                            Some(ComParamSpecificData::Regular {
                                physical_default_value: value_str.clone(),
                                dop: make_comparam_dop(full.dop.as_ref()).map(Box::new),
                            }),
                        )
                    };

                    refs.push(ComParamRef {
                        simple_value: Some(SimpleValue { value: value_str }),
                        complex_value: None,
                        com_param: Some(Box::new(ComParam {
                            com_param_type,
                            short_name: param_name.clone(),
                            long_name: None,
                            param_class: full.param_class.clone().unwrap_or_default(),
                            cp_type: ComParamStandardisationLevel::Standard,
                            display_level: None,
                            cp_usage: parse_comparam_usage(full.usage.as_deref()),
                            specific_data,
                        })),
                        protocol: None,
                        prot_stack: None,
                    });
                }
            }
        }
    }
    refs
}

/// Parse a comparam value into (simple_value, complex_value).
/// Scalars become SimpleValue, arrays become ComplexValue.
fn parse_comparam_value(val: &serde_yaml::Value) -> (Option<SimpleValue>, Option<ComplexValue>) {
    if let Some(seq) = val.as_sequence() {
        let entries = seq
            .iter()
            .map(|entry| {
                SimpleOrComplexValue::Simple(SimpleValue {
                    value: yaml_value_to_string(entry),
                })
            })
            .collect();
        (None, Some(ComplexValue { entries }))
    } else {
        (
            Some(SimpleValue {
                value: yaml_value_to_string(val),
            }),
            None,
        )
    }
}
