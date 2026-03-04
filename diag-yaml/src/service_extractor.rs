//! Inverse of service_generator: extracts YamlServices from IR DiagServices.
//!
//! The ServiceGenerator (parser side) generates DiagService IR entries from
//! declarative YAML sections. This module does the reverse: given a list of
//! DiagService entries, it reconstructs the YamlServices struct by detecting
//! UDS service patterns via the `semantic` field and SID constants.
//!
//! ## Interaction with other writer sections
//!
//! - **DiagnosticSessionControl**: only `enabled: true` is emitted (no subfunctions).
//!   The generator falls back to the `sessions:` section, which the writer already
//!   extracts from state charts.
//! - **SecurityAccess**: only `enabled: true` is emitted. The generator reads actual
//!   security levels from the `security:` section, which the writer extracts from
//!   state charts (with seed_request/key_send bytes enriched from IR services).
//! - **ECUReset, Authentication, CommunicationControl**: subfunctions are reconstructed
//!   from service names since these have no standalone writer sections.
//! - **ControlDTCSetting, ReadDTCInformation**: subfunctions are reconstructed
//!   from service names. If they match the defaults, `subfunctions: None` is emitted.
//!
//! ## Known limitations
//!
//! ServiceEntry fields that are YAML-level config hints (addressing_mode,
//! state_effects, audience, response_outputs, request_layout, communication_types,
//! nrc_on_fail, etc.) are not reconstructible from IR and will be `None`.
//! This does not affect IR -> YAML -> IR roundtrip because these fields are
//! only consumed during initial YAML parsing.

use diag_ir::types::{DiagService, ParamData, ParamType};

use crate::yaml_model::{ServiceEntry, YamlServices};

/// Extract the UDS SID byte from a service's first request parameter.
/// Returns `None` if the service has no request or no SID CodedConst param.
pub fn extract_sid(svc: &DiagService) -> Option<u8> {
    let request = svc.request.as_ref()?;
    let sid_param = request
        .params
        .iter()
        .find(|p| p.short_name == "SID_RQ" && p.param_type == ParamType::CodedConst)?;
    match &sid_param.specific_data {
        Some(ParamData::CodedConst { coded_value, .. }) => parse_hex_or_decimal(coded_value),
        _ => None,
    }
}

/// Extract a CodedConst subfunction byte from a service's request parameters.
///
/// Searches for a CodedConst param at byte position 1 (the standard UDS
/// subfunction location). Matches any param name - not just "SubFunction" -
/// because ODX-originated services may use names like "SecurityAccessType",
/// "ResetType", or "SessionType".
pub fn extract_subfunction(svc: &DiagService) -> Option<u8> {
    let request = svc.request.as_ref()?;
    let sf_param = request
        .params
        .iter()
        .find(|p| p.param_type == ParamType::CodedConst && p.byte_position == Some(1))?;
    match &sf_param.specific_data {
        Some(ParamData::CodedConst { coded_value, .. }) => parse_hex_or_decimal(coded_value),
        _ => None,
    }
}

fn parse_hex_or_decimal(s: &str) -> Option<u8> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u8::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Reconstruct YamlServices from a list of IR DiagService entries.
///
/// Groups services by their `semantic` field and SID, then builds the
/// corresponding ServiceEntry for each UDS service type.
///
/// Services that map to other YAML sections (DIDs -> `dids`, routines -> `routines`)
/// are intentionally skipped here.
pub fn extract_services(services: &[DiagService]) -> YamlServices {
    let mut yaml = YamlServices::default();

    let mut session_svcs = Vec::new();
    let mut has_security = false;
    let mut reset_svcs = Vec::new();
    let mut auth_svcs = Vec::new();
    let mut comm_svcs = Vec::new();
    let mut has_download = false;
    let mut has_upload = false;
    let mut has_tester_present = false;
    let mut dtc_setting_svcs = Vec::new();
    let mut has_clear_dtc = false;
    let mut read_dtc_svcs = Vec::new();

    for svc in services {
        if let Some(sid) = extract_sid(svc) {
            match sid {
                0x10 => session_svcs.push(svc),
                0x11 => reset_svcs.push(svc),
                0x27 => has_security = true,
                0x28 => comm_svcs.push(svc),
                0x29 => auth_svcs.push(svc),
                0x34 => has_download = true,
                0x35 => has_upload = true,
                0x36 | 0x37 => has_download = true,
                0x3E => has_tester_present = true,
                0x85 => dtc_setting_svcs.push(svc),
                0x14 => has_clear_dtc = true,
                0x19 => read_dtc_svcs.push(svc),
                0x22 | 0x2E | 0x2F | 0x31 => {} // DID/IO/routine
                _ => {}
            }
        }
    }

    // SessionControl: extract subfunctions to preserve exact names and order
    if !session_svcs.is_empty() {
        yaml.diagnostic_session_control = Some(extract_subfunction_entry(&session_svcs, "_Start"));
    }

    // SecurityAccess: enabled only, generator uses security: section
    if has_security {
        yaml.security_access = Some(ServiceEntry {
            enabled: true,
            ..Default::default()
        });
    }

    if !reset_svcs.is_empty() {
        yaml.ecu_reset = Some(extract_subfunction_entry(&reset_svcs, ""));
    }

    if !auth_svcs.is_empty() {
        yaml.authentication = Some(extract_subfunction_entry(&auth_svcs, "Authentication_"));
    }

    if !comm_svcs.is_empty() {
        yaml.communication_control = Some(extract_comm_control_entry(&comm_svcs));
    }

    if has_download {
        yaml.request_download = Some(ServiceEntry {
            enabled: true,
            ..Default::default()
        });
    }

    if has_upload {
        yaml.request_upload = Some(ServiceEntry {
            enabled: true,
            ..Default::default()
        });
    }

    if has_tester_present {
        yaml.tester_present = Some(ServiceEntry {
            enabled: true,
            ..Default::default()
        });
    }

    if !dtc_setting_svcs.is_empty() {
        yaml.control_dtc_setting =
            Some(extract_dtc_setting_entry(&dtc_setting_svcs));
    }

    if has_clear_dtc {
        yaml.clear_diagnostic_information = Some(ServiceEntry {
            enabled: true,
            ..Default::default()
        });
    }

    if !read_dtc_svcs.is_empty() {
        yaml.read_dtc_information =
            Some(extract_read_dtc_entry(&read_dtc_svcs));
    }

    yaml
}

/// Returns true if the YamlServices has at least one service type set.
pub fn has_any_service(svcs: &YamlServices) -> bool {
    svcs.diagnostic_session_control.is_some()
        || svcs.ecu_reset.is_some()
        || svcs.security_access.is_some()
        || svcs.authentication.is_some()
        || svcs.communication_control.is_some()
        || svcs.request_download.is_some()
        || svcs.request_upload.is_some()
        || svcs.tester_present.is_some()
        || svcs.control_dtc_setting.is_some()
        || svcs.clear_diagnostic_information.is_some()
        || svcs.read_dtc_information.is_some()
}

/// The 4 default CommunicationControl subtypes from service_generator.rs.
const DEFAULT_COMM_CONTROL_SUBTYPES: &[(&str, u8)] = &[
    ("EnableRxAndEnableTx", 0x00),
    ("EnableRxAndDisableTx", 0x01),
    ("DisableRxAndEnableTx", 0x02),
    ("DisableRxAndDisableTx", 0x03),
    ("EnableRxAndDisableTxWithEnhancedAddressInformation", 0x04),
    ("EnableRxAndTxWithEnhancedAddressInformation", 0x05),
];

/// Build a CommunicationControl ServiceEntry.
///
/// If the services match the default subtypes exactly, emit `subfunctions: None`
/// so the generator uses defaults. TemporalSync is handled separately via
/// the `temporal_sync` flag. Otherwise reconstruct explicit subfunctions.
fn extract_comm_control_entry(services: &[&DiagService]) -> ServiceEntry {
    // Separate TemporalSync from regular comm control services
    let regular_svcs: Vec<&DiagService> = services
        .iter()
        .filter(|svc| svc.diag_comm.short_name != "TemporalSync_Control")
        .copied()
        .collect();
    let has_temporal_sync = regular_svcs.len() < services.len();

    let is_default = regular_svcs.len() == DEFAULT_COMM_CONTROL_SUBTYPES.len()
        && DEFAULT_COMM_CONTROL_SUBTYPES.iter().all(|(name, sf_byte)| {
            let expected_name = format!("{name}_Control");
            regular_svcs.iter().any(|svc| {
                svc.diag_comm.short_name == expected_name
                    && extract_subfunction(svc) == Some(*sf_byte)
            })
        });

    if is_default {
        ServiceEntry {
            enabled: true,
            temporal_sync: if has_temporal_sync { Some(true) } else { None },
            ..Default::default()
        }
    } else {
        let mut entry = extract_subfunction_entry(&regular_svcs, "_Control");
        entry.temporal_sync = if has_temporal_sync { Some(true) } else { None };
        entry
    }
}

/// Default ControlDTCSetting subfunctions from service_generator.rs.
const DEFAULT_DTC_SETTING_SUBTYPES: &[(&str, u8)] = &[("On", 0x01), ("Off", 0x02)];

/// Build a ControlDTCSetting ServiceEntry.
///
/// If the services match the default On/Off pair exactly, emit `subfunctions: None`.
/// Otherwise reconstruct explicit subfunctions from the service names.
fn extract_dtc_setting_entry(services: &[&DiagService]) -> ServiceEntry {
    let is_default = services.len() == DEFAULT_DTC_SETTING_SUBTYPES.len()
        && DEFAULT_DTC_SETTING_SUBTYPES.iter().all(|(name, sf_byte)| {
            let expected_name = format!("DTC_Setting_Mode_{name}");
            services.iter().any(|svc| {
                svc.diag_comm.short_name == expected_name
                    && extract_subfunction(svc) == Some(*sf_byte)
            })
        });

    if is_default {
        ServiceEntry {
            enabled: true,
            ..Default::default()
        }
    } else {
        extract_subfunction_entry(services, "DTC_Setting_Mode_")
    }
}

/// Build a ReadDTCInformation ServiceEntry.
///
/// If only the default ReportDTCByStatusMask(0x02) is present, emit `subfunctions: None`.
/// Otherwise reconstruct explicit subfunctions from the service names.
fn extract_read_dtc_entry(services: &[&DiagService]) -> ServiceEntry {
    let is_default = services.len() == 1
        && services[0].diag_comm.short_name == "FaultMem_ReportDTCByStatusMask"
        && extract_subfunction(&services[0]) == Some(0x02);

    if is_default {
        ServiceEntry {
            enabled: true,
            ..Default::default()
        }
    } else {
        extract_subfunction_entry(services, "FaultMem_")
    }
}

/// Build a ServiceEntry with subfunctions extracted from service names.
///
/// Supports both prefix stripping (e.g., `Authentication_` -> `Deauthenticate`)
/// and suffix stripping (e.g., `_Start` -> `Default`, `_Control` -> `EnableRxAndTx`).
///
/// When `strip` ends with `_`, it's treated as a prefix. Otherwise as a suffix.
fn extract_subfunction_entry(services: &[&DiagService], strip: &str) -> ServiceEntry {
    let mut subfuncs = serde_yaml::Mapping::new();
    for svc in services {
        let raw = &svc.diag_comm.short_name;
        let name = if strip.ends_with('_') {
            // Prefix mode: strip "Authentication_" from "Authentication_Deauthenticate"
            raw.strip_prefix(strip).unwrap_or(raw)
        } else if strip.starts_with('_') {
            // Suffix mode: strip "_Start" from "Default_Start"
            raw.strip_suffix(strip).unwrap_or(raw)
        } else {
            raw.as_str()
        };
        if let Some(sf) = extract_subfunction(svc) {
            subfuncs.insert(
                serde_yaml::Value::String(name.to_string()),
                serde_yaml::Value::String(format!("0x{sf:02X}")),
            );
        }
    }

    ServiceEntry {
        enabled: true,
        subfunctions: if subfuncs.is_empty() {
            None
        } else {
            Some(serde_yaml::Value::Mapping(subfuncs))
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diag_ir::types::*;

    fn make_service(name: &str, semantic: &str, sid: &str) -> DiagService {
        DiagService {
            diag_comm: DiagComm {
                short_name: name.to_string(),
                semantic: semantic.to_string(),
                ..Default::default()
            },
            request: Some(Request {
                params: vec![Param {
                    short_name: "SID_RQ".to_string(),
                    param_type: ParamType::CodedConst,
                    byte_position: Some(0),
                    bit_position: Some(0),
                    specific_data: Some(ParamData::CodedConst {
                        coded_value: sid.to_string(),
                        diag_coded_type: DiagCodedType {
                            is_high_low_byte_order: true,
                            ..Default::default()
                        },
                    }),
                    ..Default::default()
                }],
                sdgs: None,
            }),
            ..Default::default()
        }
    }

    fn make_subfunction_service(
        name: &str,
        semantic: &str,
        sid: &str,
        subfunc: &str,
    ) -> DiagService {
        DiagService {
            diag_comm: DiagComm {
                short_name: name.to_string(),
                semantic: semantic.to_string(),
                ..Default::default()
            },
            request: Some(Request {
                params: vec![
                    Param {
                        short_name: "SID_RQ".to_string(),
                        param_type: ParamType::CodedConst,
                        byte_position: Some(0),
                        bit_position: Some(0),
                        specific_data: Some(ParamData::CodedConst {
                            coded_value: sid.to_string(),
                            diag_coded_type: DiagCodedType {
                                is_high_low_byte_order: true,
                                ..Default::default()
                            },
                        }),
                        ..Default::default()
                    },
                    Param {
                        short_name: "SubFunction".to_string(),
                        param_type: ParamType::CodedConst,
                        byte_position: Some(1),
                        bit_position: Some(0),
                        specific_data: Some(ParamData::CodedConst {
                            coded_value: subfunc.to_string(),
                            diag_coded_type: DiagCodedType {
                                is_high_low_byte_order: true,
                                ..Default::default()
                            },
                        }),
                        ..Default::default()
                    },
                ],
                sdgs: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_extract_sid_from_service() {
        let svc = make_service("TesterPresent", "TESTING", "0x3E");
        assert_eq!(extract_sid(&svc), Some(0x3E));
    }

    #[test]
    fn test_extract_sid_returns_none_for_no_request() {
        let svc = DiagService::default();
        assert_eq!(extract_sid(&svc), None);
    }

    #[test]
    fn test_extract_tester_present() {
        let services = vec![make_service("TesterPresent", "TESTING", "0x3E")];
        let yaml_svcs = extract_services(&services);
        assert!(yaml_svcs.tester_present.as_ref().is_some_and(|e| e.enabled));
    }

    #[test]
    fn test_extract_session_control_with_subfunctions() {
        let services = vec![
            make_subfunction_service("Default_Start", "SESSION", "0x10", "0x01"),
            make_subfunction_service("Programming_Start", "SESSION", "0x10", "0x02"),
        ];
        let yaml_svcs = extract_services(&services);
        let entry = yaml_svcs.diagnostic_session_control.as_ref().unwrap();
        assert!(entry.enabled);
        let subfuncs = entry
            .subfunctions
            .as_ref()
            .expect("subfunctions should be present");
        let mapping = subfuncs.as_mapping().unwrap();
        assert_eq!(mapping.len(), 2);
        assert_eq!(
            mapping.get(serde_yaml::Value::String("Default".into())),
            Some(&serde_yaml::Value::String("0x01".into()))
        );
        assert_eq!(
            mapping.get(serde_yaml::Value::String("Programming".into())),
            Some(&serde_yaml::Value::String("0x02".into()))
        );
    }

    #[test]
    fn test_extract_ecu_reset_with_subfunctions() {
        let services = vec![
            make_subfunction_service("HardReset", "ECU-RESET", "0x11", "0x01"),
            make_subfunction_service("SoftReset", "ECU-RESET", "0x11", "0x03"),
        ];
        let yaml_svcs = extract_services(&services);
        let entry = yaml_svcs.ecu_reset.as_ref().unwrap();
        assert!(entry.enabled);
        let subfuncs = entry.subfunctions.as_ref().unwrap();
        let map = subfuncs.as_mapping().unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(serde_yaml::Value::String("HardReset".to_string())));
        assert!(map.contains_key(serde_yaml::Value::String("SoftReset".to_string())));
    }

    #[test]
    fn test_extract_empty_services() {
        let yaml_svcs = extract_services(&[]);
        assert!(yaml_svcs.diagnostic_session_control.is_none());
        assert!(yaml_svcs.tester_present.is_none());
    }

    #[test]
    fn test_did_services_not_in_yaml_services() {
        let services = vec![
            make_service("VINDataIdentifier_Read", "DATA-IDENT", "0x22"),
            make_service("TesterPresent", "TESTING", "0x3E"),
        ];
        let yaml_svcs = extract_services(&services);
        assert!(yaml_svcs.tester_present.as_ref().is_some_and(|e| e.enabled));
        assert!(yaml_svcs.read_data_by_identifier.is_none());
    }

    #[test]
    fn test_extract_security_access_enabled_no_subfunctions() {
        let services = vec![
            make_subfunction_service(
                "SecurityAccess_RequestSeed_level_01",
                "SECURITY-ACCESS",
                "0x27",
                "0x01",
            ),
            make_subfunction_service(
                "SecurityAccess_SendKey_level_01",
                "SECURITY-ACCESS",
                "0x27",
                "0x02",
            ),
        ];
        let yaml_svcs = extract_services(&services);
        let entry = yaml_svcs.security_access.as_ref().unwrap();
        assert!(entry.enabled);
        assert!(
            entry.subfunctions.is_none(),
            "subfunctions should be None - generator uses security: section instead"
        );
    }

    #[test]
    fn test_extract_comm_control_default_subfunctions() {
        let default_services = vec![
            make_subfunction_service(
                "EnableRxAndEnableTx_Control",
                "COMMUNICATION-CONTROL",
                "0x28",
                "0x00",
            ),
            make_subfunction_service(
                "EnableRxAndDisableTx_Control",
                "COMMUNICATION-CONTROL",
                "0x28",
                "0x01",
            ),
            make_subfunction_service(
                "DisableRxAndEnableTx_Control",
                "COMMUNICATION-CONTROL",
                "0x28",
                "0x02",
            ),
            make_subfunction_service(
                "DisableRxAndDisableTx_Control",
                "COMMUNICATION-CONTROL",
                "0x28",
                "0x03",
            ),
            make_subfunction_service(
                "EnableRxAndDisableTxWithEnhancedAddressInformation_Control",
                "COMMUNICATION-CONTROL",
                "0x28",
                "0x04",
            ),
            make_subfunction_service(
                "EnableRxAndTxWithEnhancedAddressInformation_Control",
                "COMMUNICATION-CONTROL",
                "0x28",
                "0x05",
            ),
        ];
        let yaml_svcs = extract_services(&default_services);
        let entry = yaml_svcs.communication_control.as_ref().unwrap();
        assert!(entry.enabled);
        assert!(
            entry.subfunctions.is_none(),
            "Default comm control subtypes should not emit explicit subfunctions"
        );
    }

    #[test]
    fn test_extract_comm_control_custom_subfunctions() {
        let custom_services = vec![make_subfunction_service(
            "CustomMode_Control",
            "COMMUNICATION-CONTROL",
            "0x28",
            "0x10",
        )];
        let yaml_svcs = extract_services(&custom_services);
        let entry = yaml_svcs.communication_control.as_ref().unwrap();
        assert!(entry.enabled);
        assert!(
            entry.subfunctions.is_some(),
            "Non-default comm control subtypes should emit explicit subfunctions"
        );
    }

    #[test]
    fn test_has_any_service_empty() {
        let svcs = YamlServices::default();
        assert!(!has_any_service(&svcs));
    }

    #[test]
    fn test_has_any_service_with_tester_present() {
        let svcs = YamlServices {
            tester_present: Some(ServiceEntry {
                enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(has_any_service(&svcs));
    }

    #[test]
    fn test_extract_by_sid_fallback() {
        let svc = make_service("Default_Start", "", "0x10");
        let yaml_svcs = extract_services(&[svc]);
        assert!(
            yaml_svcs
                .diagnostic_session_control
                .as_ref()
                .is_some_and(|e| e.enabled),
            "Should detect DiagnosticSessionControl by SID 0x10 even without semantic"
        );
    }

    #[test]
    fn test_extract_odx_comm_control_by_sid() {
        let svc = make_service("EnableRxAndEnableTx_Control", "", "0x28");
        let yaml_svcs = extract_services(&[svc]);
        assert!(
            yaml_svcs
                .communication_control
                .as_ref()
                .is_some_and(|e| e.enabled),
            "Should detect CommunicationControl by SID 0x28"
        );
    }

    #[test]
    fn test_extract_odx_with_nonstandard_subfunction_name() {
        // ODX service with "ResetType" instead of "SubFunction"
        let svc = DiagService {
            diag_comm: DiagComm {
                short_name: "HardReset".to_string(),
                semantic: String::new(),
                ..Default::default()
            },
            request: Some(Request {
                params: vec![
                    Param {
                        short_name: "SID_RQ".to_string(),
                        param_type: ParamType::CodedConst,
                        byte_position: Some(0),
                        bit_position: Some(0),
                        specific_data: Some(ParamData::CodedConst {
                            coded_value: "0x11".to_string(),
                            diag_coded_type: DiagCodedType {
                                is_high_low_byte_order: true,
                                ..Default::default()
                            },
                        }),
                        ..Default::default()
                    },
                    Param {
                        short_name: "ResetType".to_string(),
                        param_type: ParamType::CodedConst,
                        byte_position: Some(1),
                        bit_position: Some(0),
                        specific_data: Some(ParamData::CodedConst {
                            coded_value: "0x01".to_string(),
                            diag_coded_type: DiagCodedType {
                                is_high_low_byte_order: true,
                                ..Default::default()
                            },
                        }),
                        ..Default::default()
                    },
                ],
                sdgs: None,
            }),
            ..Default::default()
        };
        let yaml_svcs = extract_services(&[svc]);
        assert!(
            yaml_svcs.ecu_reset.as_ref().is_some_and(|e| e.enabled),
            "Should detect ECUReset by SID 0x11"
        );
        assert!(
            yaml_svcs.ecu_reset.as_ref().unwrap().subfunctions.is_some(),
            "Should extract subfunction by byte position even with non-standard param name"
        );
    }
}
