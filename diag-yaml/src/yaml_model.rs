//! Serde-deserializable types matching the OpenSOVD CDA diagnostic YAML schema.
//!
//! These types capture the YAML document structure and are transformed
//! to/from the canonical IR in parser.rs and writer.rs.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Root document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlDocument {
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub meta: Option<Meta>,
    #[serde(default)]
    pub ecu: Option<Ecu>,
    #[serde(default)]
    pub audience: Option<YamlAudience>,
    #[serde(default)]
    pub sdgs: Option<BTreeMap<String, YamlSdg>>,
    #[serde(default)]
    pub comparams: Option<YamlComParams>,
    #[serde(default)]
    pub sessions: Option<BTreeMap<String, Session>>,
    #[serde(default)]
    pub state_model: Option<StateModel>,
    #[serde(default)]
    pub security: Option<BTreeMap<String, SecurityLevel>>,
    #[serde(default)]
    pub authentication: Option<Authentication>,
    #[serde(default)]
    pub identification: Option<Identification>,
    #[serde(default)]
    pub variants: Option<Variants>,
    #[serde(default)]
    pub services: Option<YamlServices>,
    #[serde(default)]
    pub access_patterns: Option<BTreeMap<String, AccessPattern>>,
    #[serde(default)]
    pub types: Option<BTreeMap<String, YamlType>>,
    #[serde(default)]
    pub dids: Option<serde_yaml::Value>,
    #[serde(default)]
    pub routines: Option<serde_yaml::Value>,
    #[serde(default)]
    pub dtc_config: Option<DtcConfig>,
    #[serde(default)]
    pub dtcs: Option<serde_yaml::Value>,
    #[serde(default)]
    pub annotations: Option<serde_yaml::Value>,
    #[serde(default, rename = "x-oem")]
    pub x_oem: Option<serde_yaml::Value>,
    #[serde(default)]
    pub ecu_jobs: Option<BTreeMap<String, EcuJob>>,
    #[serde(default)]
    pub memory: Option<YamlMemoryConfig>,
    #[serde(default)]
    pub functional_classes: Option<Vec<String>>,
}

// --- Meta ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub created: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub revisions: Vec<Revision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub changes: String,
}

// --- ECU ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ecu {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub protocols: Option<BTreeMap<String, YamlProtocol>>,
    #[serde(default)]
    pub default_addressing_mode: Option<String>,
    #[serde(default)]
    pub addressing: Option<serde_yaml::Value>,
    #[serde(default)]
    pub annotations: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlProtocol {
    #[serde(default)]
    pub protocol_short_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_default: Option<bool>,
}

// --- Audience ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlAudience {
    #[serde(default)]
    pub supplier: Option<bool>,
    #[serde(default)]
    pub development: Option<bool>,
    #[serde(default)]
    pub manufacturing: Option<bool>,
    #[serde(default)]
    pub aftersales: Option<bool>,
    #[serde(default)]
    pub aftermarket: Option<bool>,
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Per-service audience flags (OCX extension).
///
/// Used on DIDs, routines, ECU jobs, and service entries to indicate which
/// audiences a particular diagnostic service targets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YamlServiceAudience {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplier: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub development: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manufacturing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_sales: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_market: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

// --- SDGs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlSdg {
    #[serde(default)]
    pub si: String,
    #[serde(default)]
    pub caption: String,
    #[serde(default)]
    pub values: Vec<YamlSdValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlSdValue {
    #[serde(default)]
    pub si: String,
    #[serde(default)]
    pub ti: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub caption: Option<String>,
    #[serde(default)]
    pub values: Option<Vec<YamlSdValue>>,
}

// --- ComParams ---

/// Communication parameters - flat map of parameter name -> entry.
pub type YamlComParams = BTreeMap<String, ComParamEntry>;

/// A single communication parameter entry.
/// Short form: scalar value (no metadata).
/// Full form: object with optional metadata and per-protocol values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ComParamEntry {
    /// Full form with metadata and/or per-protocol values
    Full(ComParamFull),
    /// Short form: just a scalar value
    Simple(serde_yaml::Value),
}

/// Communication parameter type - distinguishes complex comparams from regular ones.
/// Other values (like "uint16", "uint8") describe data types and are treated as regular.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComParamTypeYaml {
    /// Complex comparam with nested values
    Complex,
    /// Any other type string (data type descriptors like "uint16", "uint8")
    #[serde(untagged)]
    Other(String),
}

impl ComParamTypeYaml {
    pub fn is_complex(&self) -> bool {
        matches!(self, ComParamTypeYaml::Complex)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComParamFull {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cptype: Option<ComParamTypeYaml>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_yaml::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_values: Option<Vec<serde_yaml::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dop: Option<ComParamDopDef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ComParamChild>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
}

/// Child comparam definition for complex comparams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComParamChild {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dop: Option<ComParamDopDef>,
}

/// DOP (Data Object Property) definition for comparams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComParamDopDef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(alias = "type", skip_serializing_if = "Option::is_none")]
    pub base_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

// --- Sessions ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    #[serde(default)]
    pub id: serde_yaml::Value,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub requires_unlock: Option<bool>,
    #[serde(default)]
    pub timing: Option<SessionTiming>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTiming {
    #[serde(default)]
    pub p2_ms: Option<u32>,
    #[serde(default)]
    pub p2_star_ms: Option<u32>,
}

// --- State Model ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateModel {
    #[serde(default)]
    pub initial_state: Option<StateModelState>,
    #[serde(default)]
    pub session_transitions: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    pub session_change_resets_security: Option<bool>,
    #[serde(default)]
    pub session_change_resets_authentication: Option<bool>,
    #[serde(default)]
    pub s3_timeout_resets_to_default: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateModelState {
    #[serde(default)]
    pub session: String,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub authentication_role: Option<String>,
}

// --- Security ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLevel {
    #[serde(default)]
    pub level: u32,
    #[serde(default)]
    pub seed_request: serde_yaml::Value,
    #[serde(default)]
    pub key_send: serde_yaml::Value,
    #[serde(default)]
    pub seed_size: u32,
    #[serde(default)]
    pub key_size: u32,
    #[serde(default)]
    pub algorithm: String,
    #[serde(default)]
    pub max_attempts: u32,
    #[serde(default)]
    pub delay_on_fail_ms: u32,
    #[serde(default)]
    pub allowed_sessions: Vec<String>,
}

// --- Authentication ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authentication {
    #[serde(default)]
    pub anti_brute_force: Option<serde_yaml::Value>,
    #[serde(default)]
    pub roles: Option<BTreeMap<String, serde_yaml::Value>>,
}

// --- Identification ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identification {
    #[serde(default)]
    pub expected_idents: Option<BTreeMap<String, serde_yaml::Value>>,
}

// --- Variants ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variants {
    #[serde(default)]
    pub detection_order: Vec<String>,
    #[serde(default)]
    pub fallback: Option<String>,
    #[serde(default)]
    pub definitions: Option<BTreeMap<String, VariantDef>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantDef {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub detect: Option<serde_yaml::Value>,
    #[serde(default)]
    pub inheritance: Option<serde_yaml::Value>,
    #[serde(default)]
    pub overrides: Option<serde_yaml::Value>,
    #[serde(default)]
    pub annotations: Option<serde_yaml::Value>,
}

impl VariantDef {
    /// Extract typed services from the `overrides.services` YAML value.
    /// Returns None if overrides is absent or services sub-key is absent.
    pub fn override_services(&self) -> Option<YamlServices> {
        let overrides = self.overrides.as_ref()?;
        let mapping = overrides.as_mapping()?;
        let services_val = mapping.get(serde_yaml::Value::String("services".into()))?;
        serde_yaml::from_value(services_val.clone()).ok()
    }
}

// --- Services ---

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YamlServices {
    #[serde(default, rename = "diagnosticSessionControl")]
    pub diagnostic_session_control: Option<ServiceEntry>,
    #[serde(default, rename = "ecuReset")]
    pub ecu_reset: Option<ServiceEntry>,
    #[serde(default, rename = "securityAccess")]
    pub security_access: Option<ServiceEntry>,
    #[serde(default)]
    pub authentication: Option<ServiceEntry>,
    #[serde(default, rename = "testerPresent")]
    pub tester_present: Option<ServiceEntry>,
    #[serde(default, rename = "controlDTCSetting")]
    pub control_dtc_setting: Option<ServiceEntry>,
    #[serde(default, rename = "readDataByIdentifier")]
    pub read_data_by_identifier: Option<ServiceEntry>,
    #[serde(default, rename = "writeDataByIdentifier")]
    pub write_data_by_identifier: Option<ServiceEntry>,
    #[serde(default, rename = "readDTCInformation")]
    pub read_dtc_information: Option<ServiceEntry>,
    #[serde(default, rename = "clearDiagnosticInformation")]
    pub clear_diagnostic_information: Option<ServiceEntry>,
    #[serde(default, rename = "inputOutputControlByIdentifier")]
    pub input_output_control: Option<ServiceEntry>,
    #[serde(default, rename = "routineControl")]
    pub routine_control: Option<ServiceEntry>,
    #[serde(default, rename = "readMemoryByAddress")]
    pub read_memory_by_address: Option<ServiceEntry>,
    #[serde(default, rename = "writeMemoryByAddress")]
    pub write_memory_by_address: Option<ServiceEntry>,
    #[serde(default, rename = "readScalingDataByIdentifier")]
    pub read_scaling_data: Option<ServiceEntry>,
    #[serde(default, rename = "readDataByPeriodicIdentifier")]
    pub read_data_periodic: Option<ServiceEntry>,
    #[serde(default, rename = "dynamicallyDefineDataIdentifier")]
    pub dynamically_define_did: Option<ServiceEntry>,
    #[serde(default, rename = "requestDownload")]
    pub request_download: Option<ServiceEntry>,
    #[serde(default, rename = "requestUpload")]
    pub request_upload: Option<ServiceEntry>,
    #[serde(default, rename = "transferData")]
    pub transfer_data: Option<ServiceEntry>,
    #[serde(default, rename = "requestTransferExit")]
    pub request_transfer_exit: Option<ServiceEntry>,
    #[serde(default, rename = "requestFileTransfer")]
    pub request_file_transfer: Option<ServiceEntry>,
    #[serde(default, rename = "securedDataTransmission")]
    pub secured_data_transmission: Option<ServiceEntry>,
    #[serde(default, rename = "communicationControl")]
    pub communication_control: Option<ServiceEntry>,
    #[serde(default, rename = "responseOnEvent")]
    pub response_on_event: Option<ServiceEntry>,
    #[serde(default, rename = "linkControl")]
    pub link_control: Option<ServiceEntry>,
    #[serde(default)]
    pub custom: Option<BTreeMap<String, CustomService>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceEntry {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub addressing_mode: Option<String>,
    #[serde(default)]
    pub subfunctions: Option<serde_yaml::Value>,
    #[serde(default)]
    pub state_effects: Option<serde_yaml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<YamlServiceAudience>,
    #[serde(default)]
    pub response_outputs: Option<serde_yaml::Value>,
    #[serde(default)]
    pub request_layout: Option<serde_yaml::Value>,
    #[serde(default)]
    pub control_types: Option<Vec<String>>,
    // Memory services
    #[serde(default)]
    pub alfid: Option<serde_yaml::Value>,
    #[serde(default)]
    pub max_length: Option<u32>,
    #[serde(default)]
    pub regions: Option<Vec<serde_yaml::Value>>,
    // Other optional fields
    #[serde(default)]
    pub dids: Option<serde_yaml::Value>,
    #[serde(default)]
    pub max_number_of_block_length: Option<u32>,
    #[serde(default)]
    pub max_block_sequence_counter: Option<u32>,
    #[serde(default)]
    pub max_file_size: Option<String>,
    #[serde(default)]
    pub supported_periods_ms: Option<Vec<u32>>,
    #[serde(default)]
    pub identifiers: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub max_dynamic_dids: Option<u32>,
    #[serde(default)]
    pub allow_by_identifier: Option<bool>,
    #[serde(default)]
    pub allow_by_memory_address: Option<bool>,
    #[serde(default)]
    pub communication_types: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub nrc_on_fail: Option<serde_yaml::Value>,
    #[serde(default)]
    pub max_active_events: Option<u32>,
    // CommunicationControl extras
    #[serde(default)]
    pub temporal_sync: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomService {
    #[serde(default)]
    pub sid: serde_yaml::Value,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub addressing_mode: Option<String>,
    #[serde(default)]
    pub request_layout: Option<serde_yaml::Value>,
    #[serde(default)]
    pub positive_response: Option<serde_yaml::Value>,
    #[serde(default)]
    pub negative_responses: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<YamlServiceAudience>,
}

// --- Access Patterns ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPattern {
    #[serde(default)]
    pub sessions: serde_yaml::Value,
    #[serde(default)]
    pub security: serde_yaml::Value,
    #[serde(default)]
    pub authentication: serde_yaml::Value,
    #[serde(default)]
    pub nrc_on_fail: Option<serde_yaml::Value>,
}

// --- Types ---

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct YamlType {
    #[serde(default)]
    pub base: String,
    /// CDA-compatible DOP name. When set, overrides automatic DOP name derivation.
    #[serde(default)]
    pub dop_name: Option<String>,
    #[serde(default)]
    pub endian: Option<String>,
    #[serde(default)]
    pub bit_length: Option<u32>,
    #[serde(default)]
    pub length: Option<u32>,
    #[serde(default)]
    pub min_length: Option<u32>,
    #[serde(default)]
    pub max_length: Option<u32>,
    #[serde(default)]
    pub encoding: Option<String>,
    #[serde(default)]
    pub termination: Option<String>,
    #[serde(default)]
    pub scale: Option<f64>,
    #[serde(default)]
    pub offset: Option<f64>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub constraints: Option<TypeConstraints>,
    #[serde(default)]
    pub validation: Option<serde_yaml::Value>,
    #[serde(default, rename = "enum")]
    pub enum_values: Option<serde_yaml::Value>,
    #[serde(default)]
    pub entries: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub default_text: Option<String>,
    #[serde(default)]
    pub conversion: Option<serde_yaml::Value>,
    #[serde(default)]
    pub bitmask: Option<serde_yaml::Value>,
    #[serde(default)]
    pub size: Option<u32>,
    #[serde(default)]
    pub fields: Option<Vec<serde_yaml::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeConstraints {
    #[serde(default)]
    pub internal: Option<Vec<serde_yaml::Value>>,
    #[serde(default)]
    pub physical: Option<Vec<serde_yaml::Value>>,
}

// --- DIDs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Did {
    #[serde(default)]
    pub name: String,
    /// CDA-compatible data parameter name (defaults to `name` if not specified).
    #[serde(default)]
    pub param_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub did_type: serde_yaml::Value,
    #[serde(default)]
    pub access: String,
    #[serde(default)]
    pub readable: Option<bool>,
    #[serde(default)]
    pub writable: Option<bool>,
    #[serde(default)]
    pub snapshot: Option<bool>,
    #[serde(default)]
    pub io_control: Option<serde_yaml::Value>,
    #[serde(default)]
    pub annotations: Option<serde_yaml::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<YamlServiceAudience>,
}

// --- Routines ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routine {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub access: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub parameters: Option<BTreeMap<String, RoutinePhase>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<YamlServiceAudience>,
    #[serde(default)]
    pub annotations: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutinePhase {
    #[serde(default)]
    pub input: Option<Vec<RoutineParam>>,
    #[serde(default)]
    pub output: Option<Vec<RoutineParam>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutineParam {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type", default)]
    pub param_type: serde_yaml::Value,
    #[serde(default)]
    pub semantic: Option<String>,
}

// --- DTC Config ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DtcConfig {
    #[serde(default)]
    pub status_availability_mask: Option<serde_yaml::Value>,
    #[serde(default)]
    pub snapshots: Option<BTreeMap<String, serde_yaml::Value>>,
    #[serde(default)]
    pub extended_data: Option<BTreeMap<String, serde_yaml::Value>>,
}

// --- DTCs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlDtc {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub sae: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<u32>,
    #[serde(default)]
    pub snapshots: Option<Vec<String>>,
    #[serde(default)]
    pub extended_data: Option<Vec<String>>,
    #[serde(default, rename = "x-oem")]
    pub x_oem: Option<serde_yaml::Value>,
}

// --- ECU Jobs ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcuJob {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub prog_code: Option<String>,
    #[serde(default)]
    pub input_params: Option<Vec<JobParamDef>>,
    #[serde(default)]
    pub output_params: Option<Vec<JobParamDef>>,
    #[serde(default)]
    pub neg_output_params: Option<Vec<JobParamDef>>,
    #[serde(default)]
    pub access: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<YamlServiceAudience>,
    #[serde(default)]
    pub annotations: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobParamDef {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type", default)]
    pub param_type: serde_yaml::Value,
    #[serde(default)]
    pub semantic: Option<String>,
    #[serde(default)]
    pub default_value: Option<serde_yaml::Value>,
}

// --- Memory configuration ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlMemoryConfig {
    #[serde(default)]
    pub default_address_format: Option<YamlAddressFormat>,
    #[serde(default)]
    pub regions: Option<BTreeMap<String, YamlMemoryRegion>>,
    #[serde(default)]
    pub data_blocks: Option<BTreeMap<String, YamlDataBlock>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlAddressFormat {
    #[serde(default = "default_4")]
    pub address_bytes: u8,
    #[serde(default = "default_4")]
    pub length_bytes: u8,
}

fn default_4() -> u8 {
    4
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlMemoryRegion {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub start: u64,
    pub end: u64,
    pub access: String,
    #[serde(default)]
    pub address_format: Option<YamlAddressFormat>,
    #[serde(default)]
    pub security_level: Option<String>,
    #[serde(default)]
    pub session: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlDataBlock {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "type", default = "default_download")]
    pub block_type: String,
    pub memory_address: u64,
    pub memory_size: u64,
    #[serde(default = "default_raw")]
    pub format: String,
    #[serde(default)]
    pub max_block_length: Option<u64>,
    #[serde(default)]
    pub security_level: Option<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub checksum_type: Option<String>,
}

fn default_download() -> String {
    "download".into()
}
fn default_raw() -> String {
    "raw".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comparam_entry_short_form() {
        let yaml = "false";
        let entry: ComParamEntry = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(entry, ComParamEntry::Simple(_)));
    }

    #[test]
    fn test_comparam_entry_full_form() {
        let yaml = r#"
cptype: uint16
unit: ms
default: 50
values:
  global: 50
  uds: 50
"#;
        let entry: ComParamEntry = serde_yaml::from_str(yaml).unwrap();
        match entry {
            ComParamEntry::Full(f) => {
                assert_eq!(
                    f.cptype,
                    Some(ComParamTypeYaml::Other("uint16".to_string()))
                );
                assert_eq!(f.unit.as_deref(), Some("ms"));
                let vals = f.values.unwrap();
                assert_eq!(vals.len(), 2);
            }
            ComParamEntry::Simple(_) => panic!("Expected Full variant"),
        }
    }

    #[test]
    fn test_comparam_entry_complex_values() {
        let yaml = r#"
cptype: complex
values:
  UDS_Ethernet_DoIP: ["4096", "0", "FLXC1000"]
"#;
        let entry: ComParamEntry = serde_yaml::from_str(yaml).unwrap();
        match entry {
            ComParamEntry::Full(f) => {
                let vals = f.values.unwrap();
                let v = vals.get("UDS_Ethernet_DoIP").unwrap();
                assert!(v.is_sequence());
            }
            ComParamEntry::Simple(_) => panic!("Expected Full variant"),
        }
    }

    #[test]
    fn test_yaml_comparams_map() {
        let yaml = r#"
CAN_FD_ENABLED: false
MAX_DLC: 8
P2_Client:
  cptype: uint16
  default: 50
  values:
    global: 50
"#;
        let map: YamlComParams = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(map.len(), 3);
        assert!(matches!(
            map.get("CAN_FD_ENABLED"),
            Some(ComParamEntry::Simple(_))
        ));
        assert!(matches!(map.get("P2_Client"), Some(ComParamEntry::Full(_))));
    }
}
