//! IR -> YAML writer.
//!
//! Converts the canonical DiagDatabase IR back to a YAML string using the
//! OpenSOVD CDA diagnostic YAML schema format.

use crate::service_extractor;
use crate::yaml_model::*;
use diag_ir::*;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, thiserror::Error)]
pub enum YamlWriteError {
    #[error("YAML serialization error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Write a DiagDatabase IR to a YAML string.
pub fn write_yaml(db: &DiagDatabase) -> Result<String, YamlWriteError> {
    let doc = ir_to_yaml(db);
    let yaml = serde_yaml::to_string(&doc)?;
    Ok(yaml)
}

/// Convert an IR Audience to the per-service YAML audience struct.
/// Returns `None` if all flags are false and there are no groups.
fn ir_audience_to_yaml(a: &Audience) -> Option<YamlServiceAudience> {
    let has_any = a.is_supplier
        || a.is_development
        || a.is_manufacturing
        || a.is_after_sales
        || a.is_after_market
        || !a.enabled_audiences.is_empty();
    if !has_any {
        return None;
    }
    Some(YamlServiceAudience {
        supplier: if a.is_supplier { Some(true) } else { None },
        development: if a.is_development { Some(true) } else { None },
        manufacturing: if a.is_manufacturing {
            Some(true)
        } else {
            None
        },
        after_sales: if a.is_after_sales { Some(true) } else { None },
        after_market: if a.is_after_market { Some(true) } else { None },
        groups: a
            .enabled_audiences
            .iter()
            .map(|aa| aa.short_name.clone())
            .collect(),
    })
}

/// Transform the canonical IR into a YAML document model.
fn ir_to_yaml(db: &DiagDatabase) -> YamlDocument {
    let base_variant = db
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .or(db.variants.first());
    let layer = base_variant.map(|v| &v.diag_layer);

    // Build meta from metadata map
    let meta = Some(Meta {
        author: db.metadata.get("author").cloned().unwrap_or_default(),
        domain: db.metadata.get("domain").cloned().unwrap_or_default(),
        created: db.metadata.get("created").cloned().unwrap_or_default(),
        version: db.version.clone(),
        revision: db.revision.clone(),
        description: db.metadata.get("description").cloned().unwrap_or_default(),
        tags: vec![],
        revisions: vec![],
    });

    let ecu = Some(Ecu {
        id: db.metadata.get("ecu_id").cloned().unwrap_or_default(),
        name: db.ecu_name.clone(),
        protocols: None,
        default_addressing_mode: None,
        addressing: None,
        annotations: None,
    });

    // Extract DIDs and routines from services
    let mut dids_map = serde_yaml::Mapping::new();
    let mut routines_map = serde_yaml::Mapping::new();
    // Start with type definitions from IR (authoritative source for roundtrip).
    // For string/bytes types without bit_length, compute length (bytes) from the
    // DOP to preserve the original YAML length field.
    let mut types_map: BTreeMap<String, YamlType> = db
        .type_definitions
        .iter()
        .map(|td| {
            (
                td.name.clone(),
                YamlType {
                    base: td.base.clone(),
                    bit_length: td.bit_length,
                    min_length: td.min_length,
                    max_length: td.max_length,
                    enum_values: td
                        .enum_values_json
                        .as_ref()
                        .and_then(|json| serde_json::from_str::<serde_yaml::Value>(json).ok()),
                    ..Default::default()
                },
            )
        })
        .collect();

    if let Some(layer) = layer {
        for svc in &layer.diag_services {
            if svc.diag_comm.short_name.starts_with("Routine_")
                || extract_sid_value(svc) == Some(0x31)
            {
                let rid = extract_routine_id(svc);
                let routine = service_to_routine(svc);
                let key = serde_yaml::Value::Number(serde_yaml::Number::from(rid as u64));
                routines_map.insert(key, serde_yaml::to_value(&routine).unwrap_or_default());
            } else if svc.diag_comm.short_name.ends_with("_Read") {
                let did_id = extract_did_id(svc);
                let did_name = svc
                    .diag_comm
                    .short_name
                    .strip_suffix("_Read")
                    .unwrap_or(&svc.diag_comm.short_name);

                // Extract type info from DOP if available
                let (did_type_val, type_name) = extract_did_type(svc, did_name);

                // Register named type if we extracted one
                if let Some((name, yaml_type)) = type_name {
                    types_map.entry(name).or_insert(yaml_type);
                }

                let access_name = extract_access_pattern_name(&svc.diag_comm);
                let (snap, ioc) = extract_did_extra(svc);
                let data_param_name = svc.pos_responses.first().and_then(|resp| {
                    resp.params
                        .iter()
                        .find(|p| p.param_type == ParamType::Value)
                        .map(|p| p.short_name.as_str())
                });
                let param_name = data_param_name
                    .filter(|&pn| pn != did_name)
                    .map(std::string::ToString::to_string);
                let did = Did {
                    name: did_name.to_string(),
                    param_name,
                    description: svc.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
                    did_type: did_type_val,
                    access: if access_name.is_empty() {
                        "public".into()
                    } else {
                        access_name
                    },
                    readable: Some(true),
                    writable: None, // Check if there's a matching write service
                    snapshot: snap,
                    io_control: ioc,
                    annotations: None,
                    audience: svc
                        .diag_comm
                        .audience
                        .as_ref()
                        .and_then(ir_audience_to_yaml),
                };

                let key = serde_yaml::Value::Number(serde_yaml::Number::from(did_id as u64));
                dids_map.insert(key, serde_yaml::to_value(&did).unwrap_or_default());
            }
        }

        // Mark DIDs that also have write services
        for svc in &layer.diag_services {
            if svc.diag_comm.short_name.ends_with("_Write") {
                let did_id = extract_did_id(svc);
                let key = serde_yaml::Value::Number(serde_yaml::Number::from(did_id as u64));
                if let Some(serde_yaml::Value::Mapping(did_mapping)) = dids_map.get_mut(&key) {
                    did_mapping.insert(
                        serde_yaml::Value::String("writable".into()),
                        serde_yaml::Value::Bool(true),
                    );
                }
            }
        }
    }

    // Convert SDGs
    let sdgs = layer.and_then(|l| l.sdgs.as_ref()).map(ir_sdgs_to_yaml);

    // Convert DTCs
    let dtcs = if !db.dtcs.is_empty() {
        let mut dtc_map = serde_yaml::Mapping::new();
        for dtc in &db.dtcs {
            let key = serde_yaml::Value::Number(serde_yaml::Number::from(dtc.trouble_code as u64));
            let (snapshots, extended_data) = extract_dtc_records(dtc);
            let yaml_dtc = YamlDtc {
                name: dtc.short_name.clone(),
                sae: dtc.display_trouble_code.clone(),
                description: dtc.text.as_ref().map(|t| t.value.clone()),
                severity: dtc.level,
                snapshots,
                extended_data,
                x_oem: None,
            };
            dtc_map.insert(key, serde_yaml::to_value(&yaml_dtc).unwrap_or_default());
        }
        Some(serde_yaml::Value::Mapping(dtc_map))
    } else {
        None
    };

    // Convert ECU jobs
    let ecu_jobs = layer
        .map(|l| {
            let mut jobs = BTreeMap::new();
            for job in &l.single_ecu_jobs {
                let key = job.diag_comm.short_name.to_lowercase().replace(' ', "_");
                jobs.insert(key, ir_job_to_yaml(job));
            }
            jobs
        })
        .filter(|j| !j.is_empty());

    YamlDocument {
        schema: db
            .metadata
            .get("schema")
            .cloned()
            .unwrap_or_else(|| "opensovd.cda.diagdesc/v1".into()),
        meta,
        ecu,
        audience: None,
        sdgs,
        comparams: base_variant.and_then(|v| extract_comparams(&v.diag_layer)),
        sessions: layer.and_then(|l| extract_sessions_from_state_charts(&l.state_charts)),
        state_model: layer.and_then(|l| extract_state_model_from_state_charts(&l.state_charts)),
        security: layer.and_then(|l| {
            let mut levels = extract_security_from_state_charts(&l.state_charts)?;
            enrich_security_levels(&mut levels, &l.diag_services);
            Some(levels)
        }),
        authentication: layer
            .and_then(|l| extract_authentication_from_state_charts(&l.state_charts)),
        identification: base_variant.and_then(|v| extract_identification(&v.diag_layer)),
        variants: extract_variants(db),
        services: layer
            .map(|l| service_extractor::extract_services(&l.diag_services))
            .filter(service_extractor::has_any_service),
        access_patterns: base_variant.and_then(extract_access_patterns),
        types: if types_map.is_empty() {
            None
        } else {
            Some(types_map)
        },
        dids: if dids_map.is_empty() {
            None
        } else {
            Some(serde_yaml::Value::Mapping(dids_map))
        },
        routines: if routines_map.is_empty() {
            None
        } else {
            Some(serde_yaml::Value::Mapping(routines_map))
        },
        dtc_config: base_variant.and_then(|v| extract_dtc_config(&v.diag_layer)),
        dtcs,
        annotations: base_variant.and_then(|v| extract_sdg_json(&v.diag_layer, "yaml_annotations")),
        x_oem: base_variant.and_then(|v| extract_sdg_json(&v.diag_layer, "yaml_x_oem")),
        ecu_jobs,
        memory: db.memory.as_ref().map(ir_memory_to_yaml),
        functional_classes: base_variant.and_then(|v| {
            let classes: Vec<String> = v
                .diag_layer
                .funct_classes
                .iter()
                .map(|fc| fc.short_name.clone())
                .collect();
            if classes.is_empty() {
                None
            } else {
                Some(classes)
            }
        }),
    }
}

fn extract_sid_value(svc: &DiagService) -> Option<u8> {
    let req = svc.request.as_ref()?;
    let param = req.params.iter().find(|p| p.short_name == "SID_RQ")?;
    if let Some(ParamData::CodedConst { coded_value, .. }) = &param.specific_data {
        Some(parse_coded_value(coded_value) as u8)
    } else {
        None
    }
}

/// Extract the DID ID from the request's coded const param.
fn extract_did_id(svc: &DiagService) -> u32 {
    if let Some(req) = &svc.request {
        for param in &req.params {
            if param.short_name == "DID_RQ" {
                if let Some(ParamData::CodedConst { coded_value, .. }) = &param.specific_data {
                    return parse_coded_value(coded_value);
                }
            }
        }
    }
    0
}

/// Extract the Routine ID from the request's coded const param.
fn extract_routine_id(svc: &DiagService) -> u32 {
    if let Some(req) = &svc.request {
        for param in &req.params {
            if param.short_name == "RID_RQ" {
                if let Some(ParamData::CodedConst { coded_value, .. }) = &param.specific_data {
                    return parse_coded_value(coded_value);
                }
            }
        }
    }
    0
}

fn parse_coded_value(s: &str) -> u32 {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

/// Extract DID type info from the service's response DOP.
fn extract_did_type(
    svc: &DiagService,
    did_name: &str,
) -> (serde_yaml::Value, Option<(String, YamlType)>) {
    if let Some(resp) = svc.pos_responses.first() {
        // Find the data Value param (skip SID and DID echo params)
        if let Some(param) = resp
            .params
            .iter()
            .find(|p| p.param_type == ParamType::Value)
        {
            if let Some(ParamData::Value { dop, .. }) = &param.specific_data {
                if let Some(DopData::NormalDop {
                    diag_coded_type,
                    compu_method,
                    unit_ref,
                    internal_constr,
                    ..
                }) = &dop.specific_data
                {
                    let mut yaml_type = YamlType {
                        base: String::new(),
                        dop_name: None,
                        endian: None,
                        bit_length: None,
                        length: None,
                        min_length: None,
                        max_length: None,
                        encoding: None,
                        termination: None,
                        scale: None,
                        offset: None,
                        unit: unit_ref.as_ref().map(|u| u.display_name.clone()),
                        pattern: None,
                        constraints: None,
                        validation: None,
                        enum_values: None,
                        entries: None,
                        default_text: None,
                        conversion: None,
                        bitmask: None,
                        size: None,
                        fields: None,
                    };

                    if let Some(dct) = diag_coded_type {
                        yaml_type.base = data_type_to_base(&dct.base_data_type);
                        if !dct.is_high_low_byte_order {
                            yaml_type.endian = Some("little".into());
                        } else if matches!(
                            dct.base_data_type,
                            DataType::AUint32 | DataType::AFloat32 | DataType::AFloat64
                        ) {
                            yaml_type.endian = Some("big".into());
                        }

                        match &dct.specific_data {
                            Some(DiagCodedTypeData::StandardLength { bit_length, .. }) => {
                                yaml_type.bit_length = Some(*bit_length);
                                yaml_type.base = bit_length_to_base(*bit_length, &yaml_type.base);
                            }
                            Some(DiagCodedTypeData::MinMax {
                                min_length,
                                max_length,
                                termination,
                            }) => {
                                yaml_type.min_length = Some(*min_length);
                                yaml_type.max_length = *max_length;
                                yaml_type.termination = Some(match termination {
                                    Termination::Zero => "zero".into(),
                                    Termination::HexFf => "hex_ff".into(),
                                    Termination::EndOfPdu => "end_of_pdu".into(),
                                });
                            }
                            _ => {}
                        }
                    }

                    // Extract scale/offset from CompuMethod
                    if let Some(cm) = compu_method {
                        match cm.category {
                            CompuCategory::Linear => {
                                if let Some(itp) = &cm.internal_to_phys {
                                    if let Some(scale) = itp.compu_scales.first() {
                                        if let Some(rc) = &scale.rational_co_effs {
                                            if rc.numerator.len() >= 2 {
                                                yaml_type.offset = Some(rc.numerator[0]);
                                                yaml_type.scale = Some(rc.numerator[1]);
                                            }
                                        }
                                    }
                                }
                            }
                            CompuCategory::TextTable => {
                                if let Some(itp) = &cm.internal_to_phys {
                                    let mut enum_map = serde_yaml::Mapping::new();
                                    for scale in &itp.compu_scales {
                                        if let (Some(ll), Some(consts)) =
                                            (&scale.lower_limit, &scale.consts)
                                        {
                                            let key = serde_yaml::Value::String(ll.value.clone());
                                            let val = serde_yaml::Value::String(consts.vt.clone());
                                            enum_map.insert(key, val);
                                        }
                                    }
                                    if !enum_map.is_empty() {
                                        yaml_type.enum_values =
                                            Some(serde_yaml::Value::Mapping(enum_map));
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    // Extract constraints
                    if let Some(ic) = internal_constr {
                        let mut internal = Vec::new();
                        if let Some(ll) = &ic.lower_limit {
                            internal.push(serde_yaml::Value::String(ll.value.clone()));
                        }
                        if let Some(ul) = &ic.upper_limit {
                            internal.push(serde_yaml::Value::String(ul.value.clone()));
                        }
                        if !internal.is_empty() {
                            yaml_type.constraints = Some(TypeConstraints {
                                internal: Some(internal),
                                physical: None,
                            });
                        }
                    }

                    let type_name = format!("{did_name}_type").to_lowercase();
                    let type_ref = serde_yaml::Value::String(type_name.clone());
                    return (type_ref, Some((type_name, yaml_type)));
                }
            }
        }
    }

    // Fallback: unknown type
    (serde_yaml::Value::Mapping(serde_yaml::Mapping::new()), None)
}

fn data_type_to_base(dt: &DataType) -> String {
    match dt {
        DataType::AUint32 => "u32".into(),
        DataType::AInt32 => "s32".into(),
        DataType::AFloat32 => "f32".into(),
        DataType::AFloat64 => "f64".into(),
        DataType::AAsciiString => "ascii".into(),
        DataType::AUtf8String => "utf8".into(),
        DataType::AUnicode2String => "unicode".into(),
        DataType::ABytefield => "bytes".into(),
    }
}

fn bit_length_to_base(bit_length: u32, current: &str) -> String {
    if current == "ascii" || current == "utf8" || current == "unicode" || current == "bytes" {
        return current.to_string();
    }
    let signed = current.starts_with('s') || current.starts_with('i');
    match bit_length {
        1..=8 => if signed { "s8" } else { "u8" }.into(),
        9..=16 => if signed { "s16" } else { "u16" }.into(),
        17..=32 => if signed { "s32" } else { "u32" }.into(),
        33..=64 => if signed { "s64" } else { "u64" }.into(),
        _ => current.to_string(),
    }
}

/// Convert a DiagService back to a Routine YAML model.
/// Extract the access pattern name stored in SDG metadata by the parser.
fn extract_access_pattern_name(diag_comm: &DiagComm) -> String {
    if let Some(sdgs) = &diag_comm.sdgs {
        for sdg in &sdgs.sdgs {
            if sdg.caption_sn == "access_pattern" {
                if let Some(SdOrSdg::Sd(sd)) = sdg.sds.first() {
                    return sd.value.clone();
                }
            }
        }
    }
    String::new()
}

/// Extract DID snapshot and io_control from SDG "did_extra" on a service.
fn extract_did_extra(svc: &DiagService) -> (Option<bool>, Option<serde_yaml::Value>) {
    let sdgs = match &svc.diag_comm.sdgs {
        Some(s) => s,
        None => return (None, None),
    };
    let entry = match sdgs.sdgs.iter().find(|e| e.caption_sn == "did_extra") {
        Some(e) => e,
        None => return (None, None),
    };
    let sd = match entry.sds.iter().find_map(|c| match c {
        SdOrSdg::Sd(sd) => Some(&sd.value),
        SdOrSdg::Sdg(_) => None,
    }) {
        Some(s) => s,
        None => return (None, None),
    };
    let json_val: serde_json::Value = match serde_json::from_str(sd) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let snapshot = json_val
        .get("snapshot")
        .and_then(serde_json::Value::as_bool);
    let io_control = json_val
        .get("io_control")
        .and_then(|v| serde_json::from_value::<serde_yaml::Value>(v.clone()).ok());
    (snapshot, io_control)
}

/// Extract a JSON-serialized SDG entry from a DiagLayer by caption, returning it as serde_yaml::Value.
fn extract_sdg_json(layer: &DiagLayer, caption: &str) -> Option<serde_yaml::Value> {
    let sdgs = layer.sdgs.as_ref()?;
    let entry = sdgs.sdgs.iter().find(|e| e.caption_sn == caption)?;
    let sd = entry.sds.iter().find_map(|c| match c {
        SdOrSdg::Sd(sd) => Some(&sd.value),
        SdOrSdg::Sdg(_) => None,
    })?;
    let json_val: serde_json::Value = serde_json::from_str(sd).ok()?;
    serde_json::from_value(json_val).ok()
}

/// Reconstruct access_patterns from PreConditionStateRef data on services.
/// Extract identification section from DiagLayer SDG metadata.
fn extract_identification(layer: &DiagLayer) -> Option<Identification> {
    let sdgs = layer.sdgs.as_ref()?;
    for sdg in &sdgs.sdgs {
        if sdg.caption_sn == "identification" {
            if let Some(SdOrSdg::Sd(sd)) = sdg.sds.first() {
                if let Ok(ident) = serde_yaml::from_str::<Identification>(&sd.value) {
                    return Some(ident);
                }
            }
        }
    }
    None
}

/// Extract snapshot and extended_data references from DTC SDGs.
fn extract_dtc_records(dtc: &Dtc) -> (Option<Vec<String>>, Option<Vec<String>>) {
    let sdgs = match &dtc.sdgs {
        Some(s) => s,
        None => return (None, None),
    };
    let mut snapshots = None;
    let mut extended_data = None;
    for sdg in &sdgs.sdgs {
        let names: Vec<String> = sdg
            .sds
            .iter()
            .filter_map(|sd| {
                if let SdOrSdg::Sd(sd) = sd {
                    Some(sd.value.clone())
                } else {
                    None
                }
            })
            .collect();
        if names.is_empty() {
            continue;
        }
        match sdg.caption_sn.as_str() {
            "dtc_snapshots" => snapshots = Some(names),
            "dtc_extended_data" => extended_data = Some(names),
            _ => {}
        }
    }
    (snapshots, extended_data)
}

/// Extract dtc_config from DiagLayer SDG metadata.
fn extract_dtc_config(layer: &DiagLayer) -> Option<DtcConfig> {
    let sdgs = layer.sdgs.as_ref()?;
    for sdg in &sdgs.sdgs {
        if sdg.caption_sn == "dtc_config" {
            if let Some(SdOrSdg::Sd(sd)) = sdg.sds.first() {
                if let Ok(dc) = serde_yaml::from_str::<DtcConfig>(&sd.value) {
                    return Some(dc);
                }
            }
        }
    }
    None
}

/// Reserved top-level keys in the legacy comparams format.
/// If any of these appear as parameter names after deserialization,
/// the data is in legacy format and needs conversion.
const LEGACY_COMPARAMS_KEYS: &[&str] = &["specs", "global", "doip", "can", "uds", "iso15765"];

/// Extract comparams section from DiagLayer SDG metadata.
///
/// Detects legacy format by checking for reserved keys (`specs`, `global`, etc.)
/// after deserialization. Both formats deserialize into `BTreeMap<String, ComParamEntry>`,
/// but legacy data will have protocol section names as parameter keys.
fn extract_comparams(layer: &DiagLayer) -> Option<YamlComParams> {
    let sdgs = layer.sdgs.as_ref()?;
    for sdg in &sdgs.sdgs {
        if sdg.caption_sn == "comparams" {
            if let Some(SdOrSdg::Sd(sd)) = sdg.sds.first() {
                if let Ok(parsed) = serde_yaml::from_str::<YamlComParams>(&sd.value) {
                    if parsed
                        .keys()
                        .any(|k| LEGACY_COMPARAMS_KEYS.contains(&k.as_str()))
                    {
                        // Legacy format detected - convert via dedicated struct
                        if let Ok(legacy) = serde_yaml::from_str::<LegacyYamlComParams>(&sd.value) {
                            return Some(convert_legacy_comparams(&legacy));
                        }
                    }
                    return Some(parsed);
                }
            }
        }
    }
    None
}

/// Legacy comparams format for backward compatibility.
#[derive(Debug, Clone, Deserialize)]
struct LegacyYamlComParams {
    #[serde(default)]
    specs: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(default)]
    global: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(flatten)]
    protocol_params: BTreeMap<String, serde_yaml::Value>,
}

/// Convert legacy comparams format to new flat format.
fn convert_legacy_comparams(legacy: &LegacyYamlComParams) -> YamlComParams {
    let mut result = BTreeMap::new();

    // Collect all parameter values grouped by protocol
    let mut param_values: BTreeMap<String, BTreeMap<String, serde_yaml::Value>> = BTreeMap::new();

    // Process global section
    if let Some(global) = &legacy.global {
        for (name, val) in global {
            param_values
                .entry(name.clone())
                .or_default()
                .insert("global".into(), val.clone());
        }
    }

    // Process protocol sections (doip, can, uds, iso15765, etc.)
    for (proto, params) in &legacy.protocol_params {
        if let Some(map) = params.as_mapping() {
            for (key, val) in map {
                if let Some(name) = key.as_str() {
                    param_values
                        .entry(name.to_string())
                        .or_default()
                        .insert(proto.clone(), extract_legacy_value(val));
                }
            }
        }
    }

    // Process specs section (metadata)
    if let Some(specs) = &legacy.specs {
        for (name, spec_val) in specs {
            // Check if spec uses legacy protocols format
            if let Some(protocols) = spec_val.get("protocols").and_then(|p| p.as_mapping()) {
                let mut values = BTreeMap::new();
                for (proto_key, proto_val) in protocols {
                    if let Some(proto_name) = proto_key.as_str() {
                        if let Some(v) = proto_val.get("value").and_then(|v| v.as_str()) {
                            values.insert(
                                proto_name.to_string(),
                                serde_yaml::Value::String(v.to_string()),
                            );
                        } else if let Some(seq) = proto_val
                            .get("complex_entries")
                            .and_then(|v| v.as_sequence())
                        {
                            let arr: Vec<serde_yaml::Value> = seq
                                .iter()
                                .filter_map(|e| {
                                    e.get("value")
                                        .and_then(|v| v.as_str())
                                        .map(|s| serde_yaml::Value::String(s.to_string()))
                                })
                                .collect();
                            values.insert(proto_name.to_string(), serde_yaml::Value::Sequence(arr));
                        }
                    }
                }
                if !values.is_empty() {
                    result.insert(
                        name.clone(),
                        ComParamEntry::Full(ComParamFull {
                            cptype: None,
                            unit: None,
                            description: None,
                            default: None,
                            min: None,
                            max: None,
                            allowed_values: None,
                            values: Some(values),
                            dop: None,
                            children: None,
                            param_class: None,
                            usage: None,
                        }),
                    );
                }
            } else {
                // Spec with metadata (cptype, min, max, etc.) - merge with collected values
                let values_map = param_values.remove(name);
                let cptype = spec_val.get("cptype").and_then(|v| v.as_str()).map(|s| {
                    if s == "complex" {
                        ComParamTypeYaml::Complex
                    } else {
                        ComParamTypeYaml::Other(s.to_string())
                    }
                });
                let unit = spec_val
                    .get("unit")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let description = spec_val
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let default = spec_val.get("default_value").cloned();
                let min = spec_val.get("min").and_then(serde_yaml::Value::as_f64);
                let max = spec_val.get("max").and_then(serde_yaml::Value::as_f64);

                result.insert(
                    name.clone(),
                    ComParamEntry::Full(ComParamFull {
                        cptype,
                        unit,
                        description,
                        default,
                        min,
                        max,
                        allowed_values: None,
                        values: values_map,
                        dop: None,
                        children: None,
                        param_class: None,
                        usage: None,
                    }),
                );
            }
        }
    }

    // Add remaining params that were only in protocol sections (not in specs)
    for (name, values) in param_values {
        result.entry(name).or_insert_with(|| {
            if values.len() == 1 && values.contains_key("global") {
                // Single global value -> short form
                ComParamEntry::Simple(values.into_values().next().unwrap())
            } else {
                ComParamEntry::Full(ComParamFull {
                    cptype: None,
                    unit: None,
                    description: None,
                    default: None,
                    min: None,
                    max: None,
                    allowed_values: None,
                    values: Some(values),
                    dop: None,
                    children: None,
                    param_class: None,
                    usage: None,
                })
            }
        });
    }

    result
}

/// Extract the actual value from a legacy comparam_value (which could be a plain scalar
/// or an object like `{value: 2000, type: "uint32", unit: "ms"}`).
fn extract_legacy_value(val: &serde_yaml::Value) -> serde_yaml::Value {
    if let Some(map) = val.as_mapping() {
        if let Some(v) = map.get(serde_yaml::Value::String("value".into())) {
            return v.clone();
        }
    }
    val.clone()
}

fn extract_access_patterns(variant: &Variant) -> Option<BTreeMap<String, AccessPattern>> {
    let mut patterns: BTreeMap<String, AccessPattern> = BTreeMap::new();

    for svc in &variant.diag_layer.diag_services {
        let name = extract_access_pattern_name(&svc.diag_comm);
        if name.is_empty() || patterns.contains_key(&name) {
            continue;
        }

        let refs = &svc.diag_comm.pre_condition_state_refs;

        let mut session_names: Vec<String> = Vec::new();
        let mut security_names: Vec<String> = Vec::new();
        let mut auth_names: Vec<String> = Vec::new();

        for pcsr in refs {
            // Convert CDA state name back to YAML key via state.long_name.ti
            let yaml_key = pcsr
                .state
                .as_ref()
                .and_then(|s| s.long_name.as_ref())
                .filter(|ln| !ln.ti.is_empty())
                .map_or_else(
                    || pcsr.in_param_path_short_name.to_lowercase(),
                    |ln| ln.ti.clone(),
                );
            match pcsr.value.as_str() {
                "Session" => session_names.push(yaml_key),
                "SecurityAccess" => security_names.push(yaml_key),
                "Authentication" => auth_names.push(yaml_key),
                _ => {}
            }
        }

        let sessions = if session_names.is_empty() {
            serde_yaml::Value::String("any".into())
        } else {
            serde_yaml::to_value(&session_names).unwrap_or_default()
        };
        let security = if security_names.is_empty() {
            serde_yaml::Value::String("none".into())
        } else {
            serde_yaml::to_value(&security_names).unwrap_or_default()
        };
        let authentication = if auth_names.is_empty() {
            serde_yaml::Value::String("none".into())
        } else {
            serde_yaml::to_value(&auth_names).unwrap_or_default()
        };

        patterns.insert(
            name,
            AccessPattern {
                sessions,
                security,
                authentication,
                nrc_on_fail: None,
            },
        );
    }

    if patterns.is_empty() {
        None
    } else {
        Some(patterns)
    }
}

fn service_to_routine(svc: &DiagService) -> Routine {
    let mut operations = vec![];
    if svc.request.is_some() {
        operations.push("start".into());
    }
    if !svc.pos_responses.is_empty() {
        operations.push("result".into());
    }

    let access_name = extract_access_pattern_name(&svc.diag_comm);
    Routine {
        name: svc.diag_comm.short_name.clone(),
        description: svc.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
        access: if access_name.is_empty() {
            "public".into()
        } else {
            access_name
        },
        operations,
        parameters: None, // Simplified - could reconstruct from params
        audience: svc
            .diag_comm
            .audience
            .as_ref()
            .and_then(ir_audience_to_yaml),
        annotations: None,
    }
}

/// SDG captions that are extracted into dedicated YAML sections and must not
/// appear in the generic `sdgs:` output to avoid duplication on roundtrip.
const DEDICATED_SDG_CAPTIONS: &[&str] = &[
    "identification",
    "comparams",
    "dtc_config",
    "yaml_annotations",
    "yaml_x_oem",
];

/// Convert IR SDGs to YAML SDGs.
fn ir_sdgs_to_yaml(sdgs: &Sdgs) -> BTreeMap<String, YamlSdg> {
    let mut map = BTreeMap::new();
    for (i, sdg) in sdgs.sdgs.iter().enumerate() {
        let key = if sdg.caption_sn.is_empty() {
            format!("sdg_{i}")
        } else {
            sdg.caption_sn.to_lowercase().replace(' ', "_")
        };
        if DEDICATED_SDG_CAPTIONS.contains(&key.as_str()) {
            continue;
        }
        map.insert(key, ir_sdg_to_yaml(sdg));
    }
    map
}

fn ir_sdg_to_yaml(sdg: &Sdg) -> YamlSdg {
    let values = sdg
        .sds
        .iter()
        .map(|sd_or_sdg| match sd_or_sdg {
            SdOrSdg::Sd(sd) => YamlSdValue {
                si: sd.si.clone(),
                ti: if sd.ti.is_empty() {
                    None
                } else {
                    Some(sd.ti.clone())
                },
                value: Some(sd.value.clone()),
                caption: None,
                values: None,
            },
            SdOrSdg::Sdg(nested) => {
                let nested_yaml = ir_sdg_to_yaml(nested);
                YamlSdValue {
                    si: nested.si.clone(),
                    ti: None,
                    value: None,
                    caption: Some(nested.caption_sn.clone()),
                    values: Some(nested_yaml.values),
                }
            }
        })
        .collect();

    YamlSdg {
        si: sdg.si.clone(),
        caption: sdg.caption_sn.clone(),
        values,
    }
}

/// Convert IR SingleEcuJob to YAML EcuJob.
fn ir_job_to_yaml(job: &SingleEcuJob) -> EcuJob {
    let convert_params = |params: &[JobParam]| -> Option<Vec<JobParamDef>> {
        if params.is_empty() {
            return None;
        }
        Some(
            params
                .iter()
                .map(|p| JobParamDef {
                    name: p.short_name.clone(),
                    description: p.long_name.as_ref().map(|ln| ln.value.clone()),
                    param_type: serde_yaml::Value::Null,
                    semantic: if p.semantic.is_empty() {
                        None
                    } else {
                        Some(p.semantic.clone())
                    },
                    default_value: if p.physical_default_value.is_empty() {
                        None
                    } else {
                        Some(serde_yaml::Value::String(p.physical_default_value.clone()))
                    },
                })
                .collect(),
        )
    };

    EcuJob {
        name: job.diag_comm.short_name.clone(),
        description: job.diag_comm.long_name.as_ref().map(|ln| ln.value.clone()),
        prog_code: job.prog_codes.first().map(|pc| pc.code_file.clone()),
        input_params: convert_params(&job.input_params),
        output_params: convert_params(&job.output_params),
        neg_output_params: convert_params(&job.neg_output_params),
        access: None,
        audience: job
            .diag_comm
            .audience
            .as_ref()
            .and_then(ir_audience_to_yaml),
        annotations: None,
    }
}

/// Extract sessions from a "Session" state chart.
/// State short_name is the CDA name (CamelCase), long_name.ti is the YAML key (lowercase).
fn extract_sessions_from_state_charts(
    state_charts: &[StateChart],
) -> Option<BTreeMap<String, Session>> {
    let sc = state_charts.iter().find(|sc| sc.short_name == "Session")?;
    if sc.states.is_empty() {
        return None;
    }
    let mut sessions = BTreeMap::new();
    for state in &sc.states {
        let (id_val, yaml_key, alias) = if let Some(ln) = &state.long_name {
            let id: u64 = ln.value.parse().unwrap_or(0);
            // long_name.ti stores the YAML key; short_name is the CDA alias
            let yaml_key = if ln.ti.is_empty() {
                state.short_name.to_lowercase()
            } else {
                ln.ti.clone()
            };
            // Only output alias if it differs from trivial capitalization of the key
            let alias = if state.short_name != crate::parser::capitalize_first(&yaml_key) {
                Some(state.short_name.clone())
            } else {
                None
            };
            (
                serde_yaml::Value::Number(serde_yaml::Number::from(id)),
                yaml_key,
                alias,
            )
        } else {
            (
                serde_yaml::Value::Number(serde_yaml::Number::from(0u64)),
                state.short_name.to_lowercase(),
                None,
            )
        };
        sessions.insert(
            yaml_key,
            Session {
                id: id_val,
                alias,
                requires_unlock: None,
                timing: None,
            },
        );
    }
    Some(sessions)
}

/// Extract state_model from a "Session" state chart (transitions + start state).
/// CDA names are mapped back to YAML keys via long_name.ti.
fn extract_state_model_from_state_charts(state_charts: &[StateChart]) -> Option<StateModel> {
    let sc = state_charts.iter().find(|sc| sc.short_name == "Session")?;

    // Build CDA name → YAML key mapping
    let cda_to_yaml: HashMap<&str, String> = sc
        .states
        .iter()
        .map(|s| {
            let yaml_key = s
                .long_name
                .as_ref()
                .filter(|ln| !ln.ti.is_empty())
                .map_or_else(|| s.short_name.to_lowercase(), |ln| ln.ti.clone());
            (s.short_name.as_str(), yaml_key)
        })
        .collect();

    let start_yaml = cda_to_yaml
        .get(sc.start_state_short_name_ref.as_str())
        .cloned()
        .unwrap_or_else(|| sc.start_state_short_name_ref.to_lowercase());

    let has_start = !start_yaml.is_empty() && start_yaml != "default";
    let has_transitions = !sc.state_transitions.is_empty();
    if !has_start && !has_transitions {
        return None;
    }

    let initial_state = if has_start {
        Some(StateModelState {
            session: start_yaml,
            security: None,
            authentication_role: None,
        })
    } else {
        None
    };

    let session_transitions = if has_transitions {
        let mut trans_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for t in &sc.state_transitions {
            let from = cda_to_yaml
                .get(t.source_short_name_ref.as_str())
                .cloned()
                .unwrap_or_else(|| t.source_short_name_ref.to_lowercase());
            let to = cda_to_yaml
                .get(t.target_short_name_ref.as_str())
                .cloned()
                .unwrap_or_else(|| t.target_short_name_ref.to_lowercase());
            trans_map.entry(from).or_default().push(to);
        }
        Some(trans_map)
    } else {
        None
    };

    Some(StateModel {
        initial_state,
        session_transitions,
        session_change_resets_security: None,
        session_change_resets_authentication: None,
        s3_timeout_resets_to_default: None,
    })
}

/// Extract security levels from a "SecurityAccess" state chart.
/// Skips the synthetic "Locked" state. Uses long_name.ti as the YAML key.
fn extract_security_from_state_charts(
    state_charts: &[StateChart],
) -> Option<BTreeMap<String, SecurityLevel>> {
    let sc = state_charts
        .iter()
        .find(|sc| sc.short_name == "SecurityAccess")?;
    if sc.states.is_empty() {
        return None;
    }
    let mut levels = BTreeMap::new();
    for state in &sc.states {
        // Skip the synthetic Locked state
        if state.short_name == "Locked" {
            continue;
        }
        let level_num = state
            .long_name
            .as_ref()
            .and_then(|ln| ln.value.parse::<u32>().ok())
            .unwrap_or(0);
        // Use long_name.ti as YAML key (original key), falling back to short_name
        let yaml_key = state
            .long_name
            .as_ref()
            .filter(|ln| !ln.ti.is_empty())
            .map_or_else(|| state.short_name.clone(), |ln| ln.ti.clone());
        levels.insert(
            yaml_key,
            SecurityLevel {
                level: level_num,
                seed_request: serde_yaml::Value::Null,
                key_send: serde_yaml::Value::Null,
                seed_size: 0,
                key_size: 0,
                algorithm: String::new(),
                max_attempts: 0,
                delay_on_fail_ms: 0,
                allowed_sessions: vec![],
            },
        );
    }
    Some(levels)
}

/// Enrich security levels extracted from state charts with actual seed/key
/// bytes from the SecurityAccess IR services.
///
/// The state chart only stores level names and numbers - not the UDS subfunction
/// bytes or seed/key sizes. These must be reconstructed from the service params.
fn enrich_security_levels(levels: &mut BTreeMap<String, SecurityLevel>, services: &[DiagService]) {
    for svc in services {
        if svc.diag_comm.semantic != "SECURITY-ACCESS" {
            continue;
        }

        let subfunc = match service_extractor::extract_subfunction(svc) {
            Some(sf) => sf,
            None => continue,
        };

        let name = &svc.diag_comm.short_name;

        // Determine level name from service name prefix
        let level_name = if let Some(suffix) = name.strip_prefix("SecurityAccess_RequestSeed_") {
            suffix
        } else if let Some(suffix) = name.strip_prefix("SecurityAccess_SendKey_") {
            suffix
        } else {
            continue;
        };

        let Some(level) = levels.get_mut(level_name) else {
            continue;
        };

        let is_request_seed = name.starts_with("SecurityAccess_RequestSeed_");

        if is_request_seed {
            level.seed_request = serde_yaml::Value::String(format!("0x{subfunc:02X}"));
            // Extract seed size from response's SecuritySeed Value param
            if let Some(resp) = svc.pos_responses.first() {
                if let Some(bit_len) = extract_value_param_bit_length(&resp.params, "SecuritySeed")
                {
                    level.seed_size = (bit_len / 8).max(1);
                }
            }
        } else {
            level.key_send = serde_yaml::Value::String(format!("0x{subfunc:02X}"));
            // Extract key size from request's SecurityKey Value param
            if let Some(req) = &svc.request {
                if let Some(bit_len) = extract_value_param_bit_length(&req.params, "SecurityKey") {
                    level.key_size = (bit_len / 8).max(1);
                }
            }
        }
    }
}

/// Extract the bit_length from a Value param's StandardLength DiagCodedType.
fn extract_value_param_bit_length(params: &[Param], param_name: &str) -> Option<u32> {
    let param = params
        .iter()
        .find(|p| p.short_name == param_name && p.param_type == ParamType::Value)?;
    if let Some(ParamData::Value { dop, .. }) = &param.specific_data {
        if let Some(DopData::NormalDop {
            diag_coded_type: Some(dct),
            ..
        }) = &dop.specific_data
        {
            if let Some(DiagCodedTypeData::StandardLength { bit_length, .. }) = &dct.specific_data {
                return Some(*bit_length);
            }
        }
    }
    None
}

/// Extract authentication roles from an "AuthenticationStates" state chart (semantic = "AUTHENTICATION").
fn extract_authentication_from_state_charts(state_charts: &[StateChart]) -> Option<Authentication> {
    let sc = state_charts
        .iter()
        .find(|sc| sc.short_name == "Authentication")?;
    if sc.states.is_empty() {
        return None;
    }
    let mut roles = BTreeMap::new();
    for state in &sc.states {
        let id = state
            .long_name
            .as_ref()
            .and_then(|ln| ln.value.parse::<u64>().ok())
            .unwrap_or(0);
        let mut role_map = serde_yaml::Mapping::new();
        role_map.insert(
            serde_yaml::Value::String("id".into()),
            serde_yaml::Value::Number(serde_yaml::Number::from(id)),
        );
        roles.insert(
            state.short_name.clone(),
            serde_yaml::Value::Mapping(role_map),
        );
    }
    Some(Authentication {
        anti_brute_force: None,
        roles: Some(roles),
    })
}

/// Extract variant definitions from non-base IR variants.
fn extract_variants(db: &DiagDatabase) -> Option<Variants> {
    let non_base: Vec<_> = db.variants.iter().filter(|v| !v.is_base_variant).collect();
    if non_base.is_empty() {
        return None;
    }

    let base_prefix = db
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .map(|v| format!("{}_", v.diag_layer.short_name))
        .unwrap_or_default();

    let mut detection_order = Vec::new();
    let mut definitions = BTreeMap::new();

    for variant in &non_base {
        let name = variant
            .diag_layer
            .short_name
            .strip_prefix(&base_prefix)
            .unwrap_or(&variant.diag_layer.short_name)
            .to_string();
        detection_order.push(name.clone());

        let detect = variant
            .variant_patterns
            .first()
            .and_then(|vp| vp.matching_parameters.first())
            .map(|mp| {
                let mut rpm = serde_yaml::Mapping::new();
                rpm.insert(
                    serde_yaml::Value::String("service".into()),
                    serde_yaml::Value::String(mp.diag_service.diag_comm.short_name.clone()),
                );
                rpm.insert(
                    serde_yaml::Value::String("param_path".into()),
                    serde_yaml::Value::String(mp.out_param.short_name.clone()),
                );
                rpm.insert(
                    serde_yaml::Value::String("expected_value".into()),
                    parse_expected_value(&mp.expected_value),
                );
                let mut detect_map = serde_yaml::Mapping::new();
                detect_map.insert(
                    serde_yaml::Value::String("response_param_match".into()),
                    serde_yaml::Value::Mapping(rpm),
                );
                serde_yaml::Value::Mapping(detect_map)
            });

        // Extract variant-specific services (e.g., security access on Boot_Variant)
        let variant_overrides = if !variant.diag_layer.diag_services.is_empty() {
            let yaml_services =
                service_extractor::extract_services(&variant.diag_layer.diag_services);
            if service_extractor::has_any_service(&yaml_services) {
                let services_val = serde_yaml::to_value(&yaml_services).unwrap_or_default();
                let mut overrides_map = serde_yaml::Mapping::new();
                overrides_map.insert(serde_yaml::Value::String("services".into()), services_val);
                Some(serde_yaml::Value::Mapping(overrides_map))
            } else {
                None
            }
        } else {
            None
        };

        definitions.insert(
            name,
            VariantDef {
                description: variant
                    .diag_layer
                    .long_name
                    .as_ref()
                    .map(|ln| ln.value.clone()),
                detect,
                inheritance: None,
                overrides: variant_overrides,
                annotations: None,
            },
        );
    }

    Some(Variants {
        detection_order,
        fallback: non_base.last().map(|v| v.diag_layer.short_name.clone()),
        definitions: if definitions.is_empty() {
            None
        } else {
            Some(definitions)
        },
    })
}

fn parse_expected_value(s: &str) -> serde_yaml::Value {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if let Ok(n) = u64::from_str_radix(hex, 16) {
            return serde_yaml::Value::Number(serde_yaml::Number::from(n));
        }
    }
    if let Ok(n) = s.parse::<u64>() {
        return serde_yaml::Value::Number(serde_yaml::Number::from(n));
    }
    serde_yaml::Value::String(s.to_string())
}

fn ir_memory_to_yaml(mc: &MemoryConfig) -> YamlMemoryConfig {
    let default_address_format = Some(YamlAddressFormat {
        address_bytes: mc.default_address_format.address_bytes,
        length_bytes: mc.default_address_format.length_bytes,
    });

    let regions: BTreeMap<String, YamlMemoryRegion> = mc
        .regions
        .iter()
        .map(|r| {
            let session = r.session.as_ref().map(|sessions| {
                if sessions.len() == 1 {
                    serde_yaml::Value::String(sessions[0].clone())
                } else {
                    serde_yaml::Value::Sequence(
                        sessions
                            .iter()
                            .map(|s| serde_yaml::Value::String(s.clone()))
                            .collect(),
                    )
                }
            });
            (
                r.name.clone(),
                YamlMemoryRegion {
                    name: r.name.clone(),
                    description: r.description.clone(),
                    start: r.start_address,
                    end: r.start_address + r.size,
                    access: match r.access {
                        MemoryAccess::Read => "read".into(),
                        MemoryAccess::Write => "write".into(),
                        MemoryAccess::ReadWrite => "read_write".into(),
                        MemoryAccess::Execute => "execute".into(),
                    },
                    address_format: r.address_format.map(|af| YamlAddressFormat {
                        address_bytes: af.address_bytes,
                        length_bytes: af.length_bytes,
                    }),
                    security_level: r.security_level.clone(),
                    session,
                },
            )
        })
        .collect();

    let data_blocks: BTreeMap<String, YamlDataBlock> = mc
        .data_blocks
        .iter()
        .map(|b| {
            (
                b.name.clone(),
                YamlDataBlock {
                    name: b.name.clone(),
                    description: b.description.clone(),
                    block_type: match b.block_type {
                        DataBlockType::Download => "download".into(),
                        DataBlockType::Upload => "upload".into(),
                    },
                    memory_address: b.memory_address,
                    memory_size: b.memory_size,
                    format: match b.format {
                        DataBlockFormat::Raw => "raw".into(),
                        DataBlockFormat::Encrypted => "encrypted".into(),
                        DataBlockFormat::Compressed => "compressed".into(),
                        DataBlockFormat::EncryptedCompressed => "encrypted_compressed".into(),
                    },
                    max_block_length: b.max_block_length,
                    security_level: b.security_level.clone(),
                    session: b.session.clone(),
                    checksum_type: b.checksum_type.clone(),
                },
            )
        })
        .collect();

    YamlMemoryConfig {
        default_address_format,
        regions: if regions.is_empty() {
            None
        } else {
            Some(regions)
        },
        data_blocks: if data_blocks.is_empty() {
            None
        } else {
            Some(data_blocks)
        },
    }
}
