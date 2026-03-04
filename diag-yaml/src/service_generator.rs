//! UDS service generation from the YAML `services` section.
//!
//! Each public method generates `Vec<DiagService>` for one UDS service type.

use crate::yaml_model::{SecurityLevel, Session, YamlServices};
use diag_ir::*;
use std::collections::BTreeMap;

/// Generates DiagService instances from the YAML `services` configuration.
pub struct ServiceGenerator<'a> {
    services: &'a YamlServices,
    sessions: Option<&'a BTreeMap<String, Session>>,
    security: Option<&'a BTreeMap<String, SecurityLevel>>,
}

impl<'a> ServiceGenerator<'a> {
    pub fn new(services: &'a YamlServices) -> Self {
        Self {
            services,
            sessions: None,
            security: None,
        }
    }

    pub fn with_sessions(mut self, sessions: Option<&'a BTreeMap<String, Session>>) -> Self {
        self.sessions = sessions;
        self
    }

    pub fn with_security(mut self, security: Option<&'a BTreeMap<String, SecurityLevel>>) -> Self {
        self.security = security;
        self
    }

    /// Generate all enabled services.
    pub fn generate_all(&self) -> Vec<DiagService> {
        let mut result = Vec::new();
        result.extend(self.generate_diagnostic_session_control());
        result.extend(self.generate_security_access());
        result.extend(self.generate_ecu_reset());
        result.extend(self.generate_authentication());
        result.extend(self.generate_communication_control());
        result.extend(self.generate_request_download());
        result.extend(self.generate_request_upload());
        result.extend(self.generate_tester_present());
        result.extend(self.generate_control_dtc_setting());
        result.extend(self.generate_clear_diagnostic_information());
        result.extend(self.generate_read_dtc_information());
        result
    }

    // --- Session, Security, Reset (Task 12b) ---

    /// DiagnosticSessionControl (0x10): one service per session.
    ///
    /// Service naming follows CDA convention: `{Alias}_Start` (e.g., `Default_Start`).
    /// Falls back to `{Name}_Start` if no alias is defined.
    pub fn generate_diagnostic_session_control(&self) -> Vec<DiagService> {
        let entry = match &self.services.diagnostic_session_control {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        // If subfunctions are provided explicitly, use them
        if let Some(subfuncs) = &entry.subfunctions {
            return self.session_services_from_subfunctions(subfuncs);
        }

        // Otherwise generate from sessions section
        let sessions = match self.sessions {
            Some(s) if !s.is_empty() => s,
            _ => return vec![],
        };

        sessions
            .iter()
            .map(|(name, session)| {
                let id = yaml_value_to_u8(&session.id);
                let label = session.alias.as_deref().unwrap_or(name);
                let sf = subfunction_param_name("SESSION");
                build_service(
                    &format!("{label}_Start"),
                    "SESSION",
                    vec![
                        coded_const_param("SID_RQ", 0, 8, "16"),
                        coded_const_param(sf, 1, 8, &id.to_string()),
                    ],
                    vec![
                        coded_const_param("SID_PR", 0, 8, "80"),
                        matching_request_param(sf, 1, 1),
                    ],
                )
            })
            .collect()
    }

    fn session_services_from_subfunctions(&self, subfuncs: &serde_yaml::Value) -> Vec<DiagService> {
        // Helper: derive display name from session key using sessions section alias
        let display_name = |key: &str| -> String {
            self.sessions
                .and_then(|s| s.get(key))
                .and_then(|s| s.alias.as_deref())
                .unwrap_or(key)
                .to_string()
        };

        let sf = subfunction_param_name("SESSION");
        match subfuncs {
            // Map form: {default: 0x01, programming: 0x02, extended: 0x03}
            serde_yaml::Value::Mapping(map) => map
                .iter()
                .filter_map(|(k, v)| {
                    let name = k.as_str()?;
                    let id = yaml_value_to_u8(v);
                    let label = display_name(name);
                    Some(build_service(
                        &format!("{label}_Start"),
                        "SESSION",
                        vec![
                            coded_const_param("SID_RQ", 0, 8, "16"),
                            coded_const_param(sf, 1, 8, &id.to_string()),
                        ],
                        vec![
                            coded_const_param("SID_PR", 0, 8, "80"),
                            matching_request_param(sf, 1, 1),
                        ],
                    ))
                })
                .collect(),
            // Sequence form: [0x01, 0x02, 0x03]
            serde_yaml::Value::Sequence(seq) => seq
                .iter()
                .map(|v| {
                    let id = yaml_value_to_u8(v);
                    build_service(
                        &format!("0x{id:02X}_Start"),
                        "SESSION",
                        vec![
                            coded_const_param("SID_RQ", 0, 8, "16"),
                            coded_const_param(sf, 1, 8, &id.to_string()),
                        ],
                        vec![
                            coded_const_param("SID_PR", 0, 8, "80"),
                            matching_request_param(sf, 1, 1),
                        ],
                    )
                })
                .collect(),
            _ => vec![],
        }
    }

    /// SecurityAccess (0x27): two services per security level (RequestSeed + SendKey).
    ///
    /// Service naming follows CDA convention: `RequestSeed_Level_{n}`, `SendKey_Level_{n}`
    /// where n is the security level number (not the subfunc byte).
    pub fn generate_security_access(&self) -> Vec<DiagService> {
        let entry = match &self.services.security_access {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };
        let _ = entry;
        let security = match self.security {
            Some(s) if !s.is_empty() => s,
            _ => return vec![],
        };

        let mut services = Vec::new();
        for level in security.values() {
            let seed_byte = yaml_value_to_u8(&level.seed_request);
            let key_byte = yaml_value_to_u8(&level.key_send);
            let level_num = level.level;

            services.push(build_service(
                &format!("RequestSeed_Level_{level_num}"),
                "SECURITY-ACCESS",
                vec![
                    coded_const_param("SID_RQ", 0, 8, "39"),
                    coded_const_param("SecurityAccessType", 1, 8, &seed_byte.to_string()),
                ],
                vec![
                    coded_const_param("SID_PR", 0, 8, "103"),
                    matching_request_param("SecurityAccessType", 1, 1),
                ],
            ));

            let send_key_name = format!("SendKey_Level_{level_num}");
            let mut send_key = build_service(
                &send_key_name,
                "SECURITY-ACCESS",
                vec![
                    coded_const_param("SID_RQ", 0, 8, "39"),
                    coded_const_param("SUBFUNCTION", 1, 8, &key_byte.to_string()),
                    value_param("SecurityKey", 2, (level.key_size * 8).max(8), "SecurityAccess_EndOfPduByteArray"),
                ],
                vec![
                    coded_const_param("SID_PR", 0, 8, "103"),
                    matching_request_param("SecurityAccessType", 1, 1),
                ],
            );
            send_key.neg_responses.push(standard_neg_response());
            services.push(send_key);
        }
        services
    }

    /// ECUReset (0x11): one service per configured reset type.
    ///
    /// Service naming follows CDA convention: PascalCase reset type name
    /// (e.g., `HardReset`, `SoftReset`).
    pub fn generate_ecu_reset(&self) -> Vec<DiagService> {
        let entry = match &self.services.ecu_reset {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        let sf = subfunction_param_name("ECU-RESET");
        let make = |name: &str, subfunc: u8| {
            build_service(
                name,
                "ECU-RESET",
                vec![
                    coded_const_param("SID_RQ", 0, 8, "17"),
                    coded_const_param(sf, 1, 8, &subfunc.to_string()),
                ],
                vec![
                    coded_const_param("SID_PR", 0, 8, "81"),
                    matching_request_param(sf, 1, 1),
                ],
            )
        };

        if let Some(serde_yaml::Value::Mapping(subfuncs)) = &entry.subfunctions {
            subfuncs
                .iter()
                .filter_map(|(k, v)| {
                    let name = k.as_str()?;
                    let subfunc = yaml_value_to_u8(v);
                    let pascal = to_pascal_case(name);
                    Some(make(&pascal, subfunc))
                })
                .collect()
        } else {
            vec![make("HardReset", 0x01), make("KeyOffOnReset", 0x02), make("SoftReset", 0x03)]
        }
    }

    // --- Authentication and Communication Control (Task 12c) ---

    /// Authentication (0x29): one service per configured subfunction.
    ///
    /// Service naming: `Authentication_{PascalName}` (e.g., `Authentication_Deauthenticate`).
    pub fn generate_authentication(&self) -> Vec<DiagService> {
        let entry = match &self.services.authentication {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        let subfuncs = match &entry.subfunctions {
            Some(serde_yaml::Value::Mapping(map)) => map,
            _ => return vec![],
        };

        let sf = subfunction_param_name("AUTHENTICATION");
        subfuncs
            .iter()
            .filter_map(|(k, v)| {
                let name = k.as_str()?;
                let subfunc = yaml_value_to_u8(v);
                let pascal = to_pascal_case(name);
                let response_params = if subfunc == 0x08 {
                    vec![
                        coded_const_param("SID_PR", 0, 8, "105"),
                        matching_request_param(sf, 1, 1),
                        value_param("AuthenticationReturnParameter", 2, 8, "AuthReturnParam"),
                    ]
                } else {
                    vec![
                        coded_const_param("SID_PR", 0, 8, "105"),
                        matching_request_param(sf, 1, 1),
                    ]
                };
                Some(build_service(
                    &format!("Authentication_{pascal}"),
                    "AUTHENTICATION",
                    vec![
                        coded_const_param("SID_RQ", 0, 8, "41"),
                        coded_const_param(sf, 1, 8, &subfunc.to_string()),
                    ],
                    response_params,
                ))
            })
            .collect()
    }

    /// CommunicationControl (0x28): one service per configured subfunction.
    ///
    /// Default subtypes include enhanced address info variants (0x04, 0x05).
    /// TemporalSync (0x88) is generated when `temporal_sync: true` in YAML.
    pub fn generate_communication_control(&self) -> Vec<DiagService> {
        let entry = match &self.services.communication_control {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        let mut services: Vec<DiagService> = match &entry.subfunctions {
            Some(serde_yaml::Value::Mapping(map)) => map
                .iter()
                .filter_map(|(k, v)| {
                    let name = k.as_str()?;
                    let subfunc = yaml_value_to_u8(v);
                    Some(comm_control_service(name, subfunc))
                })
                .collect(),
            Some(serde_yaml::Value::Sequence(seq)) => seq
                .iter()
                .map(|v| {
                    let subfunc = yaml_value_to_u8(v);
                    let name = comm_control_name(subfunc);
                    comm_control_service(&name, subfunc)
                })
                .collect(),
            _ => {
                // Default subtypes
                DEFAULT_COMM_CONTROL_SUBTYPES
                    .iter()
                    .map(|(name, subfunc)| comm_control_service(name, *subfunc))
                    .collect()
            }
        };

        // TemporalSync (subfunc 0x88) with extra temporalEraId parameter
        if entry.temporal_sync.unwrap_or(false) {
            let sf = subfunction_param_name("COMMUNICATION-CONTROL");
            services.push(build_service(
                "TemporalSync_Control",
                "COMMUNICATION-CONTROL",
                vec![
                    coded_const_param("SID_RQ", 0, 8, "40"),
                    coded_const_param(sf, 1, 8, "136"),
                    coded_const_param("CommunicationType", 2, 8, "1"),
                    value_param("temporalEraId", 3, 32, "temporalEraId"),
                ],
                vec![
                    coded_const_param("SID_PR", 0, 8, "104"),
                    matching_request_param(sf, 1, 1),
                ],
            ));
        }

        services
    }

    // --- Transfer data services (Task 12d) ---

    /// RequestDownload (0x34) + TransferData (0x36) + RequestTransferExit (0x37) as a group.
    pub fn generate_request_download(&self) -> Vec<DiagService> {
        match &self.services.request_download {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
        let mut req_download = build_service(
            "RequestDownload",
            "DOWNLOAD",
            vec![
                coded_const_param("SID_RQ", 0, 8, "52"),
                value_param("DataFormatIdentifier", 1, 8, "IDENTICAL_UINT_8"),
                value_param("AddressAndLengthFormatIdentifier", 2, 8, "IDENTICAL_UINT_8"),
                value_param("MemoryAddress", 3, 32, "MemoryAddressArray"),
                value_param("MemorySize", 7, 32, "MemorySizeArray"),
            ],
            vec![
                coded_const_param("SID_PR", 0, 8, "116"),
                value_param("LengthFormatIdentifier", 1, 8, "IDENTICAL_UINT_8"),
                value_param("MaxNumberOfBlockLength", 2, 32, "IDENTICAL_UINT_32"),
            ],
        );
        req_download.diag_comm.semantic = "DATA".to_string();
        vec![
            req_download,
            {
                let mut bsc_resp = matching_request_param("BlockSequenceCounter", 1, 1);
                bsc_resp.semantic = "DATA".to_string();
                build_service(
                    "TransferData",
                    "DOWNLOAD",
                    vec![
                        coded_const_param("SID_RQ", 0, 8, "54"),
                        value_param("BlockSequenceCounter", 1, 8, "IDENTICAL_UINT_8"),
                        value_param("TransferRequestParameterRecord", 1, 0, "TransferData"),
                    ],
                    vec![
                        coded_const_param("SID_PR", 0, 8, "118"),
                        bsc_resp,
                        value_param("TransferRequestParameterRecord", 1, 0, "TransferData"),
                    ],
                )
            },
            build_service(
                "TransferExit",
                "DOWNLOAD",
                vec![coded_const_param("SID_RQ", 0, 8, "55")],
                vec![coded_const_param("SID_PR", 0, 8, "119")],
            ),
        ]
    }

    /// RequestUpload (0x35) + TransferData + RequestTransferExit as a group.
    pub fn generate_request_upload(&self) -> Vec<DiagService> {
        match &self.services.request_upload {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
        vec![
            build_service(
                "RequestUpload",
                "UPLOAD",
                vec![
                    coded_const_param("SID_RQ", 0, 8, "53"),
                    value_param("DataFormatIdentifier", 1, 8, "IDENTICAL_UINT_8"),
                    value_param("AddressAndLengthFormatIdentifier", 2, 8, "IDENTICAL_UINT_8"),
                    value_param("MemoryAddress", 3, 32, "MemoryAddressArray"),
                    value_param("MemorySize", 7, 32, "MemorySizeArray"),
                ],
                vec![
                    coded_const_param("SID_PR", 0, 8, "117"),
                    value_param("LengthFormatIdentifier", 1, 8, "IDENTICAL_UINT_8"),
                    value_param("MaxNumberOfBlockLength", 2, 32, "IDENTICAL_UINT_32"),
                ],
            ),
            build_service(
                "TransferData_Upload",
                "UPLOAD",
                vec![
                    coded_const_param("SID_RQ", 0, 8, "54"),
                    value_param("BlockSequenceCounter", 1, 8, "IDENTICAL_UINT_8"),
                ],
                vec![
                    coded_const_param("SID_PR", 0, 8, "118"),
                    value_param("BlockSequenceCounter", 1, 8, "IDENTICAL_UINT_8"),
                    value_param("TransferRequestParameterRecord", 2, 0, "TransferData"),
                ],
            ),
            build_service(
                "RequestTransferExit_Upload",
                "UPLOAD",
                vec![coded_const_param("SID_RQ", 0, 8, "55")],
                vec![coded_const_param("SID_PR", 0, 8, "119")],
            ),
        ]
    }

    // --- Simple enable/disable services (Task 12a) ---

    /// TesterPresent (0x3E)
    pub fn generate_tester_present(&self) -> Vec<DiagService> {
        match &self.services.tester_present {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
        let sf = subfunction_param_name("TESTING");
        vec![build_service(
            "TesterPresent",
            "TESTING",
            vec![
                coded_const_param("SID_RQ", 0, 8, "62"),
                coded_const_param(sf, 1, 8, "0"),
            ],
            vec![
                coded_const_param("SID_PR", 0, 8, "126"),
                matching_request_param(sf, 1, 1),
            ],
        )]
    }

    /// ControlDTCSetting (0x85): one service per configured DTC setting mode.
    ///
    /// Service naming follows CDA convention: `DTC_Setting_Mode_{name}`.
    /// Subfunctions can be configured in YAML; defaults to On(0x01) and Off(0x02).
    pub fn generate_control_dtc_setting(&self) -> Vec<DiagService> {
        let entry = match &self.services.control_dtc_setting {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        let sf = subfunction_param_name("CONTROL-DTC-SETTING");
        let make = |name: &str, subfunc: u8| {
            build_service(
                &format!("DTC_Setting_Mode_{name}"),
                "CONTROL-DTC-SETTING",
                vec![
                    coded_const_param("SID_RQ", 0, 8, "133"),
                    coded_const_param(sf, 1, 8, &subfunc.to_string()),
                ],
                vec![
                    coded_const_param("SID_PR", 0, 8, "197"),
                    matching_request_param(sf, 1, 1),
                ],
            )
        };

        if let Some(serde_yaml::Value::Mapping(subfuncs)) = &entry.subfunctions {
            subfuncs
                .iter()
                .filter_map(|(k, v)| {
                    let name = k.as_str()?;
                    let subfunc = yaml_value_to_u8(v);
                    let pascal = to_pascal_case(name);
                    Some(make(&pascal, subfunc))
                })
                .collect()
        } else {
            vec![make("On", 0x01), make("Off", 0x02)]
        }
    }

    /// ClearDiagnosticInformation (0x14)
    ///
    /// Service name follows CDA convention: `FaultMem_ClearDTCs`.
    pub fn generate_clear_diagnostic_information(&self) -> Vec<DiagService> {
        match &self.services.clear_diagnostic_information {
            Some(e) if e.enabled => {}
            _ => return vec![],
        }
        vec![build_service(
            "FaultMem_ClearDTCs",
            "CLEAR-DTC",
            vec![
                coded_const_param("SID_RQ", 0, 8, "20"),
                value_param("Dtc", 1, 24, "RecordDataType"),
            ],
            vec![coded_const_param("SID_PR", 0, 8, "84")],
        )]
    }

    /// ReadDTCInformation (0x19): one service per configured subfunction.
    ///
    /// Service naming follows CDA convention: `FaultMem_{name}`.
    /// Parameter structure varies by subfunction type:
    /// - ReportDTCByStatusMask (0x02): includes DTC status mask bit params
    /// - ReportDTCSnapshotRecordByDtcNumber (0x04): includes DtcCode + RecordNr
    /// - ReportDTCExtDataRecordByDtcNumber (0x06): includes DtcCode + RecordNr
    pub fn generate_read_dtc_information(&self) -> Vec<DiagService> {
        let entry = match &self.services.read_dtc_information {
            Some(e) if e.enabled => e,
            _ => return vec![],
        };

        let build_by_subfunc = |name: &str, subfunc: u8| {
            let (req_params, resp_params) = read_dtc_params(subfunc);
            build_service(
                &format!("FaultMem_{name}"),
                "READ-DTC-INFO",
                req_params,
                resp_params,
            )
        };

        if let Some(serde_yaml::Value::Mapping(subfuncs)) = &entry.subfunctions {
            subfuncs
                .iter()
                .filter_map(|(k, v)| {
                    let name = k.as_str()?;
                    let subfunc = yaml_value_to_u8(v);
                    let pascal = to_pascal_case(name);
                    Some(build_by_subfunc(&pascal, subfunc))
                })
                .collect()
        } else {
            vec![build_by_subfunc("ReportDTCByStatusMask", 0x02)]
        }
    }
}

// --- Helper functions ---

/// Convert a camelCase string to PascalCase (capitalize first letter).
fn to_pascal_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

fn yaml_value_to_u8(v: &serde_yaml::Value) -> u8 {
    match v {
        serde_yaml::Value::Number(n) => {
            let val = n.as_u64().unwrap_or_else(|| {
                log::warn!("yaml_value_to_u8: non-u64 number {:?}, defaulting to 0", n);
                0
            });
            val as u8
        }
        serde_yaml::Value::String(s) => {
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u8::from_str_radix(hex, 16).unwrap_or_else(|e| {
                    log::warn!(
                        "yaml_value_to_u8: invalid hex '{}': {}, defaulting to 0",
                        s,
                        e
                    );
                    0
                })
            } else {
                s.parse().unwrap_or_else(|e| {
                    log::warn!(
                        "yaml_value_to_u8: invalid decimal '{}': {}, defaulting to 0",
                        s,
                        e
                    );
                    0
                })
            }
        }
        other => {
            log::warn!(
                "yaml_value_to_u8: unexpected YAML type {:?}, defaulting to 0",
                other
            );
            0
        }
    }
}

/// CDA-compatible subfunction param name based on service semantic.
fn subfunction_param_name(semantic: &str) -> &'static str {
    match semantic {
        "SESSION" => "SessionType",
        "ECU-RESET" => "ResetType",
        "COMMUNICATION-CONTROL" => "ControlType",
        "CONTROL-DTC-SETTING" => "SettingType",
        "AUTHENTICATION" => "SUBFUNCTION",
        _ => "SubFunction",
    }
}

/// CDA-compatible long_name for generated services.
fn service_long_name(short_name: &str, semantic: &str) -> Option<String> {
    match semantic {
        "COMMUNICATION-CONTROL" => {
            let base = short_name.strip_suffix("_Control").unwrap_or(short_name);
            let readable = camel_to_words(base)
                .replace("Rx", "Receive")
                .replace("Tx", "Transmit")
                .replace(" And ", " and ")
                .replace(" With ", " with ")
                .replace(" Sync", " Synchronization");
            Some(format!("Communication Control - {readable}"))
        }
        "CONTROL-DTC-SETTING" => {
            let mode = short_name.strip_prefix("DTC_Setting_Mode_").unwrap_or(short_name);
            Some(format!("DTC Setting {}", camel_to_words(mode)))
        }
        "CLEAR-DTC" => Some("Clear DTCs".to_string()),
        "READ-DTC-INFO" => {
            let name = short_name.strip_prefix("FaultMem_").unwrap_or(short_name);
            let words = camel_to_words(name)
                .replace(" Ext ", " Extended ")
                .replace(" Dtc ", " DTC ")
                .replace(" Dtc", " DTC");
            Some(words)
        }
        "DOWNLOAD" => None,
        _ => None,
    }
}

/// Convert CamelCase to space-separated words, preserving acronyms (e.g. "DTC", "DTCs").
fn camel_to_words(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut words = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '_' {
            words.push(' ');
            i += 1;
            continue;
        }
        if chars[i].is_uppercase() && !words.is_empty() && !words.ends_with(' ') {
            // Check if this starts an acronym (consecutive uppercase)
            let mut j = i;
            while j < chars.len() && chars[j].is_uppercase() {
                j += 1;
            }
            let acronym_len = j - i;
            if acronym_len > 1 {
                if j < chars.len() && chars[j].is_lowercase() {
                    // Check if it's just a plural 's' followed by uppercase or end
                    let is_plural_s = chars[j] == 's'
                        && (j + 1 >= chars.len() || chars[j + 1].is_uppercase() || chars[j + 1] == '_');
                    if is_plural_s {
                        // Keep entire acronym + 's' as one token (e.g. "DTCs")
                        words.push(' ');
                        for c in &chars[i..=j] {
                            words.push(*c);
                        }
                        i = j + 1;
                    } else {
                        words.push(' ');
                        // All but last uppercase are the acronym
                        for c in &chars[i..j - 1] {
                            words.push(*c);
                        }
                        // Last uppercase + lowercase(s) form next word
                        i = j - 1;
                    }
                } else {
                    words.push(' ');
                    for c in &chars[i..j] {
                        words.push(*c);
                    }
                    i = j;
                }
            } else {
                words.push(' ');
                words.push(chars[i]);
                i += 1;
            }
        } else {
            words.push(chars[i]);
            i += 1;
        }
    }
    words
}

/// Map service semantic to CDA-compatible functional classes.
fn semantic_to_funct_classes(semantic: &str) -> Vec<FunctClass> {
    let fc = |name: &str| FunctClass {
        short_name: name.to_string(),
    };
    match semantic {
        "SESSION" => vec![fc("Session")],
        "ECU-RESET" => vec![fc("EcuReset")],
        "COMMUNICATION-CONTROL" => vec![fc("CommCtrl")],
        "SECURITY-ACCESS" => vec![fc("SecurityAccess")],
        "AUTHENTICATION" => vec![fc("Authentication")],
        "DATA-READ" | "DATA-WRITE" => vec![fc("Ident")],
        "DOWNLOAD" => vec![fc("StandardDataTransfer")],
        "CONTROL-DTC-SETTING" => vec![fc("DtcSetting")],
        "CLEAR-DTC" | "READ-DTC-INFO" => vec![fc("FaultMem")],
        _ => vec![],
    }
}

fn build_service(
    short_name: &str,
    semantic: &str,
    request_params: Vec<Param>,
    response_params: Vec<Param>,
) -> DiagService {
    let ir_semantic = String::new();
    DiagService {
        diag_comm: DiagComm {
            short_name: short_name.to_string(),
            long_name: service_long_name(short_name, semantic).map(|v| LongName { value: v, ti: String::new() }),
            semantic: ir_semantic,
            funct_classes: semantic_to_funct_classes(semantic),
            is_executable: true,
            ..Default::default()
        },
        request: Some(Request {
            params: request_params,
            sdgs: None,
        }),
        pos_responses: vec![Response {
            response_type: ResponseType::PosResponse,
            params: response_params,
            sdgs: None,
        }],
        neg_responses: vec![],
        addressing: Addressing::Physical,
        transmission_mode: TransmissionMode::SendAndReceive,
        ..Default::default()
    }
}

fn coded_const_param(name: &str, byte_pos: u32, bit_size: u32, value: &str) -> Param {
    let semantic = if byte_pos == 0 {
        "SERVICE-ID".to_string()
    } else if matches!(name,
        "SubFunction" | "SessionType" | "ResetType" | "ControlType"
        | "SettingType" | "SUBFUNCTION" | "SecurityAccessType"
    ) {
        "SUBFUNCTION".to_string()
    } else {
        "DATA".to_string()
    };
    Param {
        short_name: name.to_string(),
        param_type: ParamType::CodedConst,
        semantic,
        byte_position: Some(byte_pos),
        bit_position: Some(0),
        specific_data: Some(ParamData::CodedConst {
            coded_value: value.to_string(),
            diag_coded_type: DiagCodedType {
                base_data_type: DataType::AUint32,
                is_high_low_byte_order: true,
                specific_data: Some(DiagCodedTypeData::StandardLength {
                    bit_length: bit_size,
                    bit_mask: vec![],
                    condensed: false,
                }),
                ..Default::default()
            },
        }),
        ..Default::default()
    }
}

fn value_param(name: &str, byte_pos: u32, bit_size: u32, dop_name: &str) -> Param {
    Param {
        short_name: name.to_string(),
        param_type: ParamType::Value,
        semantic: "DATA".to_string(),
        byte_position: Some(byte_pos),
        bit_position: Some(0),
        specific_data: Some(ParamData::Value {
            dop: Box::new(Dop {
                dop_type: DopType::Regular,
                short_name: dop_name.to_string(),
                specific_data: Some(DopData::NormalDop {
                    diag_coded_type: Some(DiagCodedType {
                        base_data_type: DataType::AUint32,
                        is_high_low_byte_order: true,
                        specific_data: Some(DiagCodedTypeData::StandardLength {
                            bit_length: bit_size,
                            bit_mask: vec![],
                            condensed: false,
                        }),
                        ..Default::default()
                    }),
                    compu_method: None,
                    unit_ref: None,
                    internal_constr: None,
                    physical_type: None,
                    phys_constr: None,
                }),
                sdgs: None,
            }),
            physical_default_value: String::new(),
        }),
        ..Default::default()
    }
}

#[allow(clippy::cast_possible_wrap)]
fn matching_request_param(name: &str, byte_pos: u32, byte_length: u32) -> Param {
    Param {
        short_name: name.to_string(),
        param_type: ParamType::MatchingRequestParam,
        semantic: "SEMANTIC".to_string(),
        byte_position: Some(byte_pos),
        bit_position: Some(0),
        specific_data: Some(ParamData::MatchingRequestParam {
            request_byte_pos: byte_pos as i32,
            byte_length,
        }),
        ..Default::default()
    }
}

/// Build subfunction-specific request and response parameters for ReadDTCInformation.
///
/// The parameter structure depends on the UDS subfunction:
/// - 0x02 (ReportDTCByStatusMask): SID + SubFunction + 8 status mask bit params
/// - 0x04 (ReportDTCSnapshotRecordByDtcNumber): SID + SubFunction + DtcCode + RecordNr
/// - 0x06 (ReportDTCExtDataRecordByDtcNumber): SID + SubFunction + DtcCode + RecordNr
/// - Other: SID + SubFunction (generic fallback)
fn read_dtc_params(subfunc: u8) -> (Vec<Param>, Vec<Param>) {
    let sf = subfunction_param_name("READ-DTC-INFO");
    let sid_rq = coded_const_param("SID_RQ", 0, 8, "25");
    let sid_pr = coded_const_param("SID_PR", 0, 8, "89");
    let subfunc_rq = coded_const_param(sf, 1, 8, &subfunc.to_string());
    let subfunc_echo = matching_request_param(sf, 1, 1);

    match subfunc {
        0x02 => {
            // ReportDTCByStatusMask: status mask bits as individual parameters
            let status_bit_names = [
                "testFailed",
                "testFailedThisOperationCycle",
                "pendingDTC",
                "confirmedDTC",
                "testNotCompletedSinceLastClear",
                "testFailedSinceLastClear",
                "testNotCompletedThisOperationCycle",
                "warningIndicatorRequested",
            ];
            let mut req = vec![sid_rq, subfunc_rq];
            for (i, name) in status_bit_names.iter().enumerate() {
                req.push(value_param(name, 2, 1, "TrueFalseDop"));
                // Bit position differentiates them within the same byte
                if let Some(p) = req.last_mut() {
                    p.bit_position = Some(i as u32);
                }
            }
            let mut resp = vec![sid_pr, subfunc_echo];
            resp.push(value_param("DTCAndStatusRecord", 3, 0, ""));
            for (i, name) in status_bit_names.iter().enumerate() {
                let mut p = value_param(name, 2, 1, "TrueFalseDop");
                p.bit_position = Some(i as u32);
                resp.push(p);
            }
            (req, resp)
        }
        0x04 | 0x06 => {
            // ReportDTCSnapshot/ExtData: DTC code + record number
            let req = vec![
                sid_rq,
                subfunc_rq,
                value_param("DtcCode", 2, 24, "RecordDataType"),
                value_param("DTCSnapshotRecordNr", 5, 8, "DtcSnapshotRecordDop"),
            ];
            let resp = vec![
                sid_pr,
                subfunc_echo,
                value_param("DTCAndStatusRecord", 2, 32, ""),
            ];
            (req, resp)
        }
        _ => {
            // Generic fallback
            let req = vec![sid_rq, subfunc_rq];
            let resp = vec![sid_pr, subfunc_echo];
            (req, resp)
        }
    }
}

/// Generate a standard UDS negative response.
///
/// CDA requires negative responses with specific parameter names:
/// - `SID_NR` (byte 0): CodedConst 0x7F (negative response SID)
/// - `SIDRQ_NR` (byte 1): MatchingRequestParam with semantic `SERVICEIDRQ`
/// - `NRC` (byte 2): Value param with DOP name `NRC_{short_name}` (CDA template)
fn standard_neg_response() -> Response {
    let mut sidrq = matching_request_param("SIDRQ_NR", 1, 1);
    sidrq.semantic = "SERVICEIDRQ".to_string();
    Response {
        response_type: ResponseType::NegResponse,
        params: vec![
            coded_const_param("SID_NR", 0, 8, "127"),
            sidrq,
            value_param("NRC", 2, 8, "NRC_{short_name}"),
        ],
        sdgs: None,
    }
}

const DEFAULT_COMM_CONTROL_SUBTYPES: &[(&str, u8)] = &[
    ("EnableRxAndEnableTx", 0x00),
    ("EnableRxAndDisableTx", 0x01),
    ("DisableRxAndEnableTx", 0x02),
    ("DisableRxAndDisableTx", 0x03),
    ("EnableRxAndDisableTxWithEnhancedAddressInformation", 0x04),
    ("EnableRxAndTxWithEnhancedAddressInformation", 0x05),
];

fn comm_control_name(subfunc: u8) -> String {
    DEFAULT_COMM_CONTROL_SUBTYPES
        .iter()
        .find(|(_, v)| *v == subfunc)
        .map_or_else(
            || format!("0x{subfunc:02X}"),
            |(name, _)| (*name).to_string(),
        )
}

fn comm_control_service(name: &str, subfunc: u8) -> DiagService {
    let pascal = to_pascal_case(name);
    let sf = subfunction_param_name("COMMUNICATION-CONTROL");
    build_service(
        &format!("{pascal}_Control"),
        "COMMUNICATION-CONTROL",
        vec![
            coded_const_param("SID_RQ", 0, 8, "40"),
            coded_const_param(sf, 1, 8, &subfunc.to_string()),
            coded_const_param("CommunicationType", 2, 8, "1"),
        ],
        vec![
            coded_const_param("SID_PR", 0, 8, "104"),
            matching_request_param(sf, 1, 1),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yaml_model::ServiceEntry;

    fn services_with(configure: impl FnOnce(&mut YamlServices)) -> YamlServices {
        let mut svc = YamlServices::default();
        configure(&mut svc);
        svc
    }

    fn enabled_entry() -> ServiceEntry {
        ServiceEntry {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn test_tester_present_generation() {
        let svc = services_with(|s| s.tester_present = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_tester_present();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].diag_comm.short_name, "TesterPresent");
        let req = services[0].request.as_ref().unwrap();
        assert_eq!(req.params[0].short_name, "SID_RQ");
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
            assert_eq!(coded_value, "62");
        } else {
            panic!("expected CodedConst for SID_RQ");
        }
    }

    #[test]
    fn test_control_dtc_setting_generation() {
        let svc = services_with(|s| s.control_dtc_setting = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_control_dtc_setting();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].diag_comm.short_name, "DTC_Setting_Mode_On");
        assert_eq!(services[1].diag_comm.short_name, "DTC_Setting_Mode_Off");
    }

    #[test]
    fn test_clear_dtc_generation() {
        let svc = services_with(|s| s.clear_diagnostic_information = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_clear_diagnostic_information();
        assert_eq!(services.len(), 1);
        assert_eq!(
            services[0].diag_comm.short_name,
            "FaultMem_ClearDTCs"
        );
    }

    #[test]
    fn test_read_dtc_info_generation() {
        let svc = services_with(|s| s.read_dtc_information = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_read_dtc_information();
        assert_eq!(services.len(), 1);
        assert_eq!(
            services[0].diag_comm.short_name,
            "FaultMem_ReportDTCByStatusMask"
        );
    }

    #[test]
    fn test_disabled_service_generates_nothing() {
        let svc = YamlServices::default();
        let generator = ServiceGenerator::new(&svc);
        assert!(generator.generate_all().is_empty());
    }

    #[test]
    fn test_session_control_from_subfunctions_map() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("default".into(), serde_yaml::Value::Number(1.into()));
            map.insert("extended".into(), serde_yaml::Value::Number(3.into()));
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.diagnostic_session_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_diagnostic_session_control();
        assert_eq!(services.len(), 2);
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "default_Start")
        );
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "extended_Start")
        );
    }

    #[test]
    fn test_session_control_from_subfunctions_seq() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            entry.subfunctions = Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::Number(1.into()),
                serde_yaml::Value::Number(2.into()),
            ]));
            s.diagnostic_session_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_diagnostic_session_control();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].diag_comm.short_name, "0x01_Start");
    }

    #[test]
    fn test_session_control_from_sessions_section() {
        let svc = services_with(|s| {
            s.diagnostic_session_control = Some(enabled_entry());
        });
        let mut sessions = BTreeMap::new();
        sessions.insert(
            "default".into(),
            Session {
                id: serde_yaml::Value::Number(1.into()),
                alias: None,
                requires_unlock: None,
                timing: None,
            },
        );
        sessions.insert(
            "programming".into(),
            Session {
                id: serde_yaml::Value::Number(2.into()),
                alias: None,
                requires_unlock: None,
                timing: None,
            },
        );
        let generator = ServiceGenerator::new(&svc).with_sessions(Some(&sessions));
        let services = generator.generate_diagnostic_session_control();
        assert_eq!(services.len(), 2);
        // Response should include SID and subfunc echo
        let resp = &services[0].pos_responses[0];
        assert_eq!(resp.params.len(), 2); // SID, subfunc echo
    }

    #[test]
    fn test_security_access_generation() {
        let svc = services_with(|s| s.security_access = Some(enabled_entry()));
        let mut sec = BTreeMap::new();
        sec.insert(
            "level_01".into(),
            SecurityLevel {
                level: 1,
                seed_request: serde_yaml::Value::Number(1.into()),
                key_send: serde_yaml::Value::Number(2.into()),
                seed_size: 4,
                key_size: 4,
                algorithm: String::new(),
                max_attempts: 0,
                delay_on_fail_ms: 0,
                allowed_sessions: vec![],
            },
        );
        let generator = ServiceGenerator::new(&svc).with_security(Some(&sec));
        let services = generator.generate_security_access();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].diag_comm.short_name, "RequestSeed_Level_1");
        assert_eq!(services[1].diag_comm.short_name, "SendKey_Level_1");

        // Verify seed subfunc byte
        let req = services[0].request.as_ref().unwrap();
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[1].specific_data {
            assert_eq!(coded_value, "1");
        } else {
            panic!("expected CodedConst for subfunc");
        }
    }

    #[test]
    fn test_ecu_reset_from_subfunctions() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("hardReset".into(), serde_yaml::Value::Number(1.into()));
            map.insert("softReset".into(), serde_yaml::Value::Number(3.into()));
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.ecu_reset = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_ecu_reset();
        assert_eq!(services.len(), 2);
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "HardReset")
        );
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "SoftReset")
        );
    }

    #[test]
    fn test_ecu_reset_defaults() {
        let svc = services_with(|s| s.ecu_reset = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_ecu_reset();
        assert_eq!(services.len(), 3); // hardReset, keyOffOnReset, softReset
    }

    #[test]
    fn test_authentication_from_subfunctions() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("deAuthenticate".into(), serde_yaml::Value::Number(0.into()));
            map.insert(
                "verifyCertificateUnidirectional".into(),
                serde_yaml::Value::Number(1.into()),
            );
            map.insert(
                "proofOfOwnership".into(),
                serde_yaml::Value::Number(3.into()),
            );
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.authentication = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_authentication();
        assert_eq!(services.len(), 3);
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "Authentication_DeAuthenticate")
        );
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "Authentication_ProofOfOwnership")
        );
        // Verify SID
        let req = services[0].request.as_ref().unwrap();
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
            assert_eq!(coded_value, "41");
        }
    }

    #[test]
    fn test_authentication_disabled() {
        let svc = services_with(|_| {}); // no authentication entry
        let generator = ServiceGenerator::new(&svc);
        assert!(generator.generate_authentication().is_empty());
    }

    #[test]
    fn test_communication_control_from_sequence() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            entry.subfunctions = Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::Number(0.into()),
                serde_yaml::Value::Number(1.into()),
                serde_yaml::Value::Number(3.into()),
            ]));
            s.communication_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_communication_control();
        assert_eq!(services.len(), 3);
        assert_eq!(
            services[0].diag_comm.short_name,
            "EnableRxAndEnableTx_Control"
        );
        assert_eq!(
            services[1].diag_comm.short_name,
            "EnableRxAndDisableTx_Control"
        );
        assert_eq!(
            services[2].diag_comm.short_name,
            "DisableRxAndDisableTx_Control"
        );
        // Verify SID
        let req = services[0].request.as_ref().unwrap();
        if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
            assert_eq!(coded_value, "40");
        }
    }

    #[test]
    fn test_communication_control_defaults() {
        let svc = services_with(|s| s.communication_control = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_communication_control();
        assert_eq!(services.len(), 6); // 6 default subtypes (including enhanced address info)
    }

    #[test]
    fn test_communication_control_from_map() {
        let svc = services_with(|s| {
            let mut entry = enabled_entry();
            let mut map = serde_yaml::Mapping::new();
            map.insert("enableRxAndTx".into(), serde_yaml::Value::Number(0.into()));
            map.insert("disableRxAndTx".into(), serde_yaml::Value::Number(3.into()));
            entry.subfunctions = Some(serde_yaml::Value::Mapping(map));
            s.communication_control = Some(entry);
        });
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_communication_control();
        assert_eq!(services.len(), 2);
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "EnableRxAndTx_Control")
        );
        assert!(
            services
                .iter()
                .any(|s| s.diag_comm.short_name == "DisableRxAndTx_Control")
        );
    }

    #[test]
    fn test_request_download_group() {
        let svc = services_with(|s| s.request_download = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_request_download();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].diag_comm.short_name, "RequestDownload");
        assert_eq!(services[1].diag_comm.short_name, "TransferData");
        assert_eq!(services[2].diag_comm.short_name, "TransferExit");
        // Verify SIDs
        let check_sid = |svc: &DiagService, expected: &str| {
            let req = svc.request.as_ref().unwrap();
            if let Some(ParamData::CodedConst { coded_value, .. }) = &req.params[0].specific_data {
                assert_eq!(
                    coded_value, expected,
                    "SID mismatch for {}",
                    svc.diag_comm.short_name
                );
            }
        };
        check_sid(&services[0], "52");
        check_sid(&services[1], "54");
        check_sid(&services[2], "55");
    }

    #[test]
    fn test_request_upload_group() {
        let svc = services_with(|s| s.request_upload = Some(enabled_entry()));
        let generator = ServiceGenerator::new(&svc);
        let services = generator.generate_request_upload();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].diag_comm.short_name, "RequestUpload");
        assert_eq!(services[1].diag_comm.short_name, "TransferData_Upload");
        assert_eq!(
            services[2].diag_comm.short_name,
            "RequestTransferExit_Upload"
        );
    }

    #[test]
    fn test_request_download_disabled() {
        let svc = services_with(|_| {});
        let generator = ServiceGenerator::new(&svc);
        assert!(generator.generate_request_download().is_empty());
        assert!(generator.generate_request_upload().is_empty());
    }
}
