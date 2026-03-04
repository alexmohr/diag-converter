use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// --- Top-level ---

/// Root IR type, maps to FBS EcuData
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DiagDatabase {
    pub version: String,
    pub ecu_name: String,
    pub revision: String,
    pub metadata: BTreeMap<String, String>,
    pub variants: Vec<Variant>,
    pub functional_groups: Vec<FunctionalGroup>,
    pub dtcs: Vec<Dtc>,
    pub memory: Option<MemoryConfig>,
    pub type_definitions: Vec<TypeDefinition>,
}

// --- Variant system ---

/// Maps to FBS Variant
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Variant {
    pub diag_layer: DiagLayer,
    pub is_base_variant: bool,
    pub variant_patterns: Vec<VariantPattern>,
    pub parent_refs: Vec<ParentRef>,
}

/// Maps to FBS FunctionalGroup
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionalGroup {
    pub diag_layer: DiagLayer,
    pub parent_refs: Vec<ParentRef>,
}

/// Maps to FBS EcuSharedData
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EcuSharedData {
    pub diag_layer: DiagLayer,
}

/// Maps to FBS DiagLayer
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DiagLayer {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub funct_classes: Vec<FunctClass>,
    pub com_param_refs: Vec<ComParamRef>,
    pub diag_services: Vec<DiagService>,
    pub single_ecu_jobs: Vec<SingleEcuJob>,
    pub state_charts: Vec<StateChart>,
    pub additional_audiences: Vec<AdditionalAudience>,
    pub sdgs: Option<Sdgs>,
}

/// Maps to FBS ParentRef
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParentRef {
    pub ref_type: ParentRefType,
    pub not_inherited_diag_comm_short_names: Vec<String>,
    pub not_inherited_variables_short_names: Vec<String>,
    pub not_inherited_dops_short_names: Vec<String>,
    pub not_inherited_tables_short_names: Vec<String>,
    pub not_inherited_global_neg_responses_short_names: Vec<String>,
}

/// Maps to FBS ParentRefType union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParentRefType {
    Variant(Box<Variant>),
    Protocol(Box<Protocol>),
    FunctionalGroup(Box<FunctionalGroup>),
    TableDop(Box<TableDop>),
    EcuSharedData(Box<EcuSharedData>),
}

/// Maps to FBS VariantPattern
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VariantPattern {
    pub matching_parameters: Vec<MatchingParameter>,
}

/// Maps to FBS MatchingParameter
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchingParameter {
    pub expected_value: String,
    pub diag_service: Box<DiagService>,
    pub out_param: Box<Param>,
    pub use_physical_addressing: Option<bool>,
}

// --- Services ---

/// Maps to FBS DiagComm
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DiagComm {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub semantic: String,
    pub funct_classes: Vec<FunctClass>,
    pub sdgs: Option<Sdgs>,
    pub diag_class_type: DiagClassType,
    pub pre_condition_state_refs: Vec<PreConditionStateRef>,
    pub state_transition_refs: Vec<StateTransitionRef>,
    pub protocols: Vec<Protocol>,
    pub audience: Option<Audience>,
    pub is_mandatory: bool,
    pub is_executable: bool,
    pub is_final: bool,
}

/// Maps to FBS DiagService
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DiagService {
    pub diag_comm: DiagComm,
    pub request: Option<Request>,
    pub pos_responses: Vec<Response>,
    pub neg_responses: Vec<Response>,
    pub is_cyclic: bool,
    pub is_multiple: bool,
    pub addressing: Addressing,
    pub transmission_mode: TransmissionMode,
    pub com_param_refs: Vec<ComParamRef>,
}

/// Maps to FBS SingleEcuJob
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SingleEcuJob {
    pub diag_comm: DiagComm,
    pub prog_codes: Vec<ProgCode>,
    pub input_params: Vec<JobParam>,
    pub output_params: Vec<JobParam>,
    pub neg_output_params: Vec<JobParam>,
}

/// Maps to FBS Request
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub params: Vec<Param>,
    pub sdgs: Option<Sdgs>,
}

/// Maps to FBS Response
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub response_type: ResponseType,
    pub params: Vec<Param>,
    pub sdgs: Option<Sdgs>,
}

// --- Parameters ---

/// Maps to FBS Param
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Param {
    pub id: u32,
    pub param_type: ParamType,
    pub short_name: String,
    pub semantic: String,
    pub sdgs: Option<Sdgs>,
    pub physical_default_value: String,
    pub byte_position: Option<u32>,
    pub bit_position: Option<u32>,
    pub specific_data: Option<ParamData>,
}

/// Maps to FBS ParamSpecificData union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParamData {
    CodedConst {
        coded_value: String,
        diag_coded_type: DiagCodedType,
    },
    Dynamic,
    LengthKeyRef {
        dop: Box<Dop>,
    },
    MatchingRequestParam {
        request_byte_pos: i32,
        byte_length: u32,
    },
    NrcConst {
        coded_values: Vec<String>,
        diag_coded_type: DiagCodedType,
    },
    PhysConst {
        phys_constant_value: String,
        dop: Box<Dop>,
    },
    Reserved {
        bit_length: u32,
    },
    System {
        dop: Box<Dop>,
        sys_param: String,
    },
    TableEntry {
        param: Box<Param>,
        target: TableEntryRowFragment,
        table_row: Box<TableRow>,
    },
    TableKey {
        table_key_reference: TableKeyReference,
    },
    TableStruct {
        table_key: Box<Param>,
    },
    Value {
        physical_default_value: String,
        dop: Box<Dop>,
    },
}

// --- DOPs ---

/// Maps to FBS DOP
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dop {
    pub dop_type: DopType,
    pub short_name: String,
    pub sdgs: Option<Sdgs>,
    pub specific_data: Option<DopData>,
}

/// Maps to FBS SpecificDOPData union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DopData {
    NormalDop {
        compu_method: Option<CompuMethod>,
        diag_coded_type: Option<DiagCodedType>,
        physical_type: Option<PhysicalType>,
        internal_constr: Option<InternalConstr>,
        unit_ref: Option<Unit>,
        phys_constr: Option<InternalConstr>,
    },
    EndOfPduField {
        max_number_of_items: Option<u32>,
        min_number_of_items: Option<u32>,
        field: Option<Field>,
    },
    StaticField {
        fixed_number_of_items: u32,
        item_byte_size: u32,
        field: Option<Field>,
    },
    EnvDataDesc {
        param_short_name: String,
        param_path_short_name: String,
        env_datas: Vec<Dop>,
    },
    EnvData {
        dtc_values: Vec<u32>,
        params: Vec<Param>,
    },
    DtcDop {
        diag_coded_type: Option<DiagCodedType>,
        physical_type: Option<PhysicalType>,
        compu_method: Option<CompuMethod>,
        dtcs: Vec<Dtc>,
        is_visible: bool,
    },
    Structure {
        params: Vec<Param>,
        byte_size: Option<u32>,
        is_visible: bool,
    },
    MuxDop {
        byte_position: u32,
        switch_key: Option<SwitchKey>,
        default_case: Option<DefaultCase>,
        cases: Vec<Case>,
        is_visible: bool,
    },
    DynamicLengthField {
        offset: u32,
        field: Option<Field>,
        determine_number_of_items: Option<DetermineNumberOfItems>,
    },
}

/// Maps to FBS Field
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub basic_structure: Option<Box<Dop>>,
    pub env_data_desc: Option<Box<Dop>>,
    pub is_visible: bool,
}

/// Maps to FBS SwitchKey
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwitchKey {
    pub byte_position: u32,
    pub bit_position: Option<u32>,
    pub dop: Box<Dop>,
}

/// Maps to FBS DefaultCase
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DefaultCase {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub structure: Option<Box<Dop>>,
}

/// Maps to FBS Case
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Case {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub structure: Option<Box<Dop>>,
    pub lower_limit: Option<Limit>,
    pub upper_limit: Option<Limit>,
}

/// Maps to FBS DetermineNumberOfItems
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetermineNumberOfItems {
    pub byte_position: u32,
    pub bit_position: u32,
    pub dop: Box<Dop>,
}

// --- Type system ---

/// Maps to FBS DiagCodedType
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DiagCodedType {
    pub type_name: DiagCodedTypeName,
    pub base_type_encoding: String,
    pub base_data_type: DataType,
    pub is_high_low_byte_order: bool,
    pub specific_data: Option<DiagCodedTypeData>,
}

/// Maps to FBS SpecificDataType union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DiagCodedTypeData {
    LeadingLength {
        bit_length: u32,
    },
    MinMax {
        min_length: u32,
        max_length: Option<u32>,
        termination: Termination,
    },
    ParamLength {
        length_key: Box<Param>,
    },
    StandardLength {
        bit_length: u32,
        bit_mask: Vec<u8>,
        condensed: bool,
    },
}

/// Maps to FBS CompuMethod
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompuMethod {
    pub category: CompuCategory,
    pub internal_to_phys: Option<CompuInternalToPhys>,
    pub phys_to_internal: Option<CompuPhysToInternal>,
}

/// Maps to FBS CompuInternalToPhys
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompuInternalToPhys {
    pub compu_scales: Vec<CompuScale>,
    pub prog_code: Option<ProgCode>,
    pub compu_default_value: Option<CompuDefaultValue>,
}

/// Maps to FBS CompuPhysToInternal
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompuPhysToInternal {
    pub prog_code: Option<ProgCode>,
    pub compu_scales: Vec<CompuScale>,
    pub compu_default_value: Option<CompuDefaultValue>,
}

/// Maps to FBS CompuScale
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompuScale {
    pub short_label: Option<Text>,
    pub lower_limit: Option<Limit>,
    pub upper_limit: Option<Limit>,
    pub inverse_values: Option<CompuValues>,
    pub consts: Option<CompuValues>,
    pub rational_co_effs: Option<CompuRationalCoEffs>,
}

/// Maps to FBS CompuValues
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompuValues {
    pub v: Option<f64>,
    pub vt: String,
    pub vt_ti: String,
}

/// Maps to FBS CompuRationalCoEffs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompuRationalCoEffs {
    pub numerator: Vec<f64>,
    pub denominator: Vec<f64>,
}

/// Maps to FBS CompuDefaultValue
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompuDefaultValue {
    pub values: Option<CompuValues>,
    pub inverse_values: Option<CompuValues>,
}

/// Maps to FBS PhysicalType
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalType {
    pub precision: Option<u32>,
    pub base_data_type: PhysicalTypeDataType,
    pub display_radix: Radix,
}

/// Maps to FBS Limit
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limit {
    pub value: String,
    pub interval_type: IntervalType,
}

/// Maps to FBS InternalConstr
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InternalConstr {
    pub lower_limit: Option<Limit>,
    pub upper_limit: Option<Limit>,
    pub scale_constrs: Vec<ScaleConstr>,
}

/// Maps to FBS ScaleConstr
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScaleConstr {
    pub short_label: Option<Text>,
    pub lower_limit: Option<Limit>,
    pub upper_limit: Option<Limit>,
    pub validity: ValidType,
}

/// Maps to FBS Unit
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Unit {
    pub short_name: String,
    pub display_name: String,
    pub factor_si_to_unit: Option<f64>,
    pub offset_si_to_unit: Option<f64>,
    pub physical_dimension: Option<PhysicalDimension>,
}

/// Maps to FBS PhysicalDimension
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalDimension {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub length_exp: Option<i32>,
    pub mass_exp: Option<i32>,
    pub time_exp: Option<i32>,
    pub current_exp: Option<i32>,
    pub temperature_exp: Option<i32>,
    pub molar_amount_exp: Option<i32>,
    pub luminous_intensity_exp: Option<i32>,
}

// --- DTCs ---

/// Maps to FBS DTC
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Dtc {
    pub short_name: String,
    pub trouble_code: u32,
    pub display_trouble_code: String,
    pub text: Option<Text>,
    pub level: Option<u32>,
    pub sdgs: Option<Sdgs>,
    pub is_temporary: bool,
}

// --- Tables ---

/// Maps to FBS TableDop
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TableDop {
    pub semantic: String,
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub key_label: String,
    pub struct_label: String,
    pub key_dop: Option<Box<Dop>>,
    pub rows: Vec<TableRow>,
    pub diag_comm_connectors: Vec<TableDiagCommConnector>,
    pub sdgs: Option<Sdgs>,
}

/// Maps to FBS TableRow
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TableRow {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub key: String,
    pub dop: Option<Box<Dop>>,
    pub structure: Option<Box<Dop>>,
    pub sdgs: Option<Sdgs>,
    pub audience: Option<Audience>,
    pub funct_class_refs: Vec<FunctClass>,
    pub state_transition_refs: Vec<StateTransitionRef>,
    pub pre_condition_state_refs: Vec<PreConditionStateRef>,
    pub is_executable: bool,
    pub semantic: String,
    pub is_mandatory: bool,
    pub is_final: bool,
}

/// Maps to FBS TableDiagCommConnector
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableDiagCommConnector {
    pub diag_comm: DiagServiceOrJob,
    pub semantic: String,
}

/// Maps to FBS DiagServiceOrJob union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DiagServiceOrJob {
    DiagService(Box<DiagService>),
    SingleEcuJob(Box<SingleEcuJob>),
}

/// Maps to FBS TableKeyReference union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TableKeyReference {
    TableDop(Box<TableDop>),
    TableRow(Box<TableRow>),
}

// --- Protocols and ComParams ---

/// Maps to FBS Protocol
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Protocol {
    pub diag_layer: DiagLayer,
    pub com_param_spec: Option<ComParamSpec>,
    pub prot_stack: Option<ProtStack>,
    pub parent_refs: Vec<Protocol>,
}

/// Maps to FBS ComParamSpec
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComParamSpec {
    pub prot_stacks: Vec<ProtStack>,
}

/// Maps to FBS ProtStack
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtStack {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub pdu_protocol_type: String,
    pub physical_link_type: String,
    pub comparam_subset_refs: Vec<ComParamSubSet>,
}

/// Maps to FBS ComParamSubSet
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComParamSubSet {
    pub com_params: Vec<ComParam>,
    pub complex_com_params: Vec<ComParam>,
    pub data_object_props: Vec<Dop>,
    pub unit_spec: Option<UnitSpec>,
}

/// Maps to FBS ComParamRef
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComParamRef {
    pub simple_value: Option<SimpleValue>,
    pub complex_value: Option<ComplexValue>,
    pub com_param: Option<Box<ComParam>>,
    pub protocol: Option<Box<Protocol>>,
    pub prot_stack: Option<Box<ProtStack>>,
}

/// Maps to FBS ComParam
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComParam {
    pub com_param_type: ComParamType,
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub param_class: String,
    pub cp_type: ComParamStandardisationLevel,
    pub display_level: Option<u32>,
    pub cp_usage: ComParamUsage,
    pub specific_data: Option<ComParamSpecificData>,
}

/// Maps to FBS ComParamSpecificData union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ComParamSpecificData {
    Regular {
        physical_default_value: String,
        dop: Option<Box<Dop>>,
    },
    Complex {
        com_params: Vec<ComParam>,
        complex_physical_default_values: Vec<ComplexValue>,
        allow_multiple_values: bool,
    },
}

// --- State charts ---

/// Maps to FBS StateChart
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateChart {
    pub short_name: String,
    pub semantic: String,
    pub state_transitions: Vec<StateTransition>,
    pub start_state_short_name_ref: String,
    pub states: Vec<State>,
}

/// Maps to FBS State
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub short_name: String,
    pub long_name: Option<LongName>,
}

/// Maps to FBS StateTransition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateTransition {
    pub short_name: String,
    pub source_short_name_ref: String,
    pub target_short_name_ref: String,
}

/// Maps to FBS StateTransitionRef
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateTransitionRef {
    pub value: String,
    pub state_transition: Option<StateTransition>,
}

/// Maps to FBS PreConditionStateRef
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreConditionStateRef {
    pub value: String,
    pub in_param_if_short_name: String,
    pub in_param_path_short_name: String,
    pub state: Option<State>,
}

// --- Misc types ---

/// Maps to FBS ProgCode
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgCode {
    pub code_file: String,
    pub encryption: String,
    pub syntax: String,
    pub revision: String,
    pub entrypoint: String,
    pub libraries: Vec<Library>,
}

/// Maps to FBS Library
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Library {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub code_file: String,
    pub encryption: String,
    pub syntax: String,
    pub entry_point: String,
}

/// Maps to FBS JobParam
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobParam {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub physical_default_value: String,
    pub dop_base: Option<Box<Dop>>,
    pub semantic: String,
}

/// Maps to FBS UnitSpec
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitSpec {
    pub unit_groups: Vec<UnitGroup>,
    pub units: Vec<Unit>,
    pub physical_dimensions: Vec<PhysicalDimension>,
    pub sdgs: Option<Sdgs>,
}

/// Maps to FBS UnitGroup
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitGroup {
    pub short_name: String,
    pub long_name: Option<LongName>,
    pub unit_refs: Vec<Unit>,
}

/// Maps to FBS SimpleValue
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimpleValue {
    pub value: String,
}

/// Maps to FBS ComplexValue
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplexValue {
    pub entries: Vec<SimpleOrComplexValue>,
}

/// Maps to FBS SimpleOrComplexValueEntry union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SimpleOrComplexValue {
    Simple(SimpleValue),
    Complex(Box<ComplexValue>),
}

// --- Text types ---

/// Maps to FBS Text
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Text {
    pub value: String,
    pub ti: String,
}

/// Maps to FBS LongName
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LongName {
    pub value: String,
    pub ti: String,
}

/// Maps to FBS SD
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sd {
    pub value: String,
    pub si: String,
    pub ti: String,
}

/// Maps to FBS SDxorSDG union
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SdOrSdg {
    Sd(Sd),
    Sdg(Sdg),
}

/// Maps to FBS SDG
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sdg {
    pub caption_sn: String,
    pub sds: Vec<SdOrSdg>,
    pub si: String,
}

/// Maps to FBS SDGS
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sdgs {
    pub sdgs: Vec<Sdg>,
}

/// Maps to FBS Audience
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Audience {
    pub enabled_audiences: Vec<AdditionalAudience>,
    pub disabled_audiences: Vec<AdditionalAudience>,
    pub is_supplier: bool,
    pub is_development: bool,
    pub is_manufacturing: bool,
    pub is_after_sales: bool,
    pub is_after_market: bool,
}

/// Maps to FBS AdditionalAudience
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdditionalAudience {
    pub short_name: String,
    pub long_name: Option<LongName>,
}

/// Maps to FBS FunctClass
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctClass {
    pub short_name: String,
}

// --- Enums ---

/// Maps to FBS DiagCodedTypeName
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DiagCodedTypeName {
    LeadingLengthInfoType,
    MinMaxLengthType,
    ParamLengthInfoType,
    #[default]
    StandardLengthType,
}

/// Maps to FBS DataType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DataType {
    AInt32,
    #[default]
    AUint32,
    AFloat32,
    AAsciiString,
    AUtf8String,
    AUnicode2String,
    ABytefield,
    AFloat64,
}

/// Maps to FBS Termination
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Termination {
    EndOfPdu,
    Zero,
    HexFf,
}

/// Maps to FBS IntervalType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntervalType {
    Open,
    Closed,
    Infinite,
}

/// Maps to FBS CompuCategory
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompuCategory {
    Identical,
    Linear,
    ScaleLinear,
    TextTable,
    CompuCode,
    TabIntp,
    RatFunc,
    ScaleRatFunc,
}

/// Maps to FBS PhysicalTypeDataType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhysicalTypeDataType {
    AInt32,
    AUint32,
    AFloat32,
    AAsciiString,
    AUtf8String,
    AUnicode2String,
    ABytefield,
    AFloat64,
}

/// Maps to FBS Radix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Radix {
    Hex,
    Dec,
    Bin,
    Oct,
}

/// Maps to FBS ValidType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidType {
    Valid,
    NotValid,
    NotDefined,
    NotAvailable,
}

/// Maps to FBS DOPType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DopType {
    Regular,
    EnvDataDesc,
    Mux,
    DynamicEndMarkerField,
    DynamicLengthField,
    EndOfPduField,
    StaticField,
    EnvData,
    Structure,
    Dtc,
}

/// Maps to FBS ParamType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ParamType {
    #[default]
    CodedConst,
    Dynamic,
    LengthKey,
    MatchingRequestParam,
    NrcConst,
    PhysConst,
    Reserved,
    System,
    TableEntry,
    TableKey,
    TableStruct,
    Value,
}

/// Maps to FBS TableEntryRowFragment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TableEntryRowFragment {
    Key,
    Struct,
}

/// Maps to FBS DiagClassType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DiagClassType {
    #[default]
    StartComm,
    StopComm,
    VariantIdentification,
    ReadDynDefMessage,
    DynDefMessage,
    ClearDynDefMessage,
}

/// Maps to FBS ResponseType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    PosResponse,
    NegResponse,
    GlobalNegResponse,
}

/// Maps to FBS Addressing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Addressing {
    Functional,
    #[default]
    Physical,
    FunctionalOrPhysical,
}

/// Maps to FBS TransmissionMode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TransmissionMode {
    SendOnly,
    ReceiveOnly,
    #[default]
    SendAndReceive,
    SendOrReceive,
}

/// Maps to FBS ComParamType
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComParamType {
    Regular,
    Complex,
}

/// Maps to FBS ComParamStandardisationLevel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComParamStandardisationLevel {
    Standard,
    OemSpecific,
    Optional,
    OemOptional,
}

/// Maps to FBS ComParamUsage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComParamUsage {
    EcuSoftware,
    EcuComm,
    Application,
    Tester,
}

// --- Memory configuration ---

/// Memory configuration for the ECU (ISO 14229 memory operations)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryConfig {
    pub default_address_format: AddressFormat,
    pub regions: Vec<MemoryRegion>,
    pub data_blocks: Vec<DataBlock>,
}

/// Address and length format for memory operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressFormat {
    pub address_bytes: u8,
    pub length_bytes: u8,
}

impl Default for AddressFormat {
    fn default() -> Self {
        Self {
            address_bytes: 4,
            length_bytes: 4,
        }
    }
}

/// Memory access permissions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum MemoryAccess {
    #[default]
    Read,
    Write,
    ReadWrite,
    Execute,
}

/// A memory region in the ECU
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub name: String,
    pub description: Option<String>,
    pub start_address: u64,
    pub size: u64,
    pub access: MemoryAccess,
    pub address_format: Option<AddressFormat>,
    pub security_level: Option<String>,
    pub session: Option<Vec<String>>,
}

/// Type of data block transfer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DataBlockType {
    #[default]
    Download,
    Upload,
}

/// Data format/compression for block transfers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DataBlockFormat {
    #[default]
    Raw,
    Encrypted,
    Compressed,
    EncryptedCompressed,
}

/// A data block for transfer operations (RequestDownload/RequestUpload)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataBlock {
    pub name: String,
    pub description: Option<String>,
    pub block_type: DataBlockType,
    pub memory_address: u64,
    pub memory_size: u64,
    pub format: DataBlockFormat,
    pub max_block_length: Option<u64>,
    pub security_level: Option<String>,
    pub session: Option<String>,
    pub checksum_type: Option<String>,
}

/// A named type definition for YAML roundtrip.
/// Stores the base type, bit_length, enum_values etc. from the YAML `types:` section.
/// The enum_values is stored as JSON string to avoid introducing serde_yaml dependency in diag-ir.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct TypeDefinition {
    pub name: String,
    pub base: String,
    pub bit_length: Option<u32>,
    pub min_length: Option<u32>,
    pub max_length: Option<u32>,
    pub enum_values_json: Option<String>,
    pub description: Option<String>,
}
