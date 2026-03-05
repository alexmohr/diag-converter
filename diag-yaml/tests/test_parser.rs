use diag_yaml::parse_yaml;

#[test]
fn test_parse_minimal_yaml() {
    let content = include_str!("../../test-fixtures/yaml/minimal-ecu.yml");
    let db = parse_yaml(content).unwrap();
    assert_eq!(db.ecu_name, "Minimal ECU");
    assert!(!db.variants.is_empty(), "should have at least one variant");
    // Minimal ECU has 3 types defined: did_id_type, ascii_short, raw_bytes_fixed
    // No DIDs, so no services generated from DIDs
    // But services section enables some standard services
}

#[test]
fn test_parse_example_ecm() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    assert_eq!(db.ecu_name, "Engine Control Module");
    assert!(!db.variants.is_empty());

    // ECM has many DIDs which generate read services
    let services = &db.variants[0].diag_layer.diag_services;
    assert!(
        !services.is_empty(),
        "ECM should have generated services from DIDs"
    );

    // Check VIN read service exists
    let vin_svc = services
        .iter()
        .find(|s| s.diag_comm.short_name == "VIN_Read");
    assert!(vin_svc.is_some(), "should have VIN_Read service");

    // Check that writable DIDs generate write services
    let write_svc = services
        .iter()
        .find(|s| s.diag_comm.short_name.ends_with("_Write"));
    assert!(
        write_svc.is_some(),
        "should have at least one write service"
    );

    // Check routines are converted
    let routine_svc = services
        .iter()
        .find(|s| s.diag_comm.short_name == "ClearAdaptiveValues");
    assert!(
        routine_svc.is_some(),
        "should have ClearAdaptiveValues routine"
    );

    // Check DTCs
    assert!(!db.dtcs.is_empty(), "ECM should have DTCs");
    let misfire = db
        .dtcs
        .iter()
        .find(|d| d.short_name == "RandomMisfireDetected");
    assert!(misfire.is_some(), "should have RandomMisfireDetected DTC");

    // Check ECU jobs
    let jobs = &db.variants[0].diag_layer.single_ecu_jobs;
    assert!(!jobs.is_empty(), "ECM should have ECU jobs");
    let flash_job = jobs.iter().find(|j| j.diag_comm.short_name == "FlashECU");
    assert!(flash_job.is_some(), "should have FlashECU job");
}

#[test]
fn test_parse_preserves_metadata() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    assert_eq!(db.revision, "1.1.0");
    assert_eq!(
        db.metadata.get("author").map(std::string::String::as_str),
        Some("CDA Team")
    );
    assert_eq!(
        db.metadata.get("domain").map(std::string::String::as_str),
        Some("Variant")
    );
}

#[test]
fn test_parse_dtc_severity() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    let crankshaft = db
        .dtcs
        .iter()
        .find(|d| d.short_name == "CrankshaftPositionCorrelation")
        .unwrap();
    assert_eq!(crankshaft.level, Some(1));
    assert_eq!(crankshaft.display_trouble_code, "P0335");
}

#[test]
fn test_parse_type_with_enum() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    // The session_type uses an enum, which should result in TextTable CompuMethod
    let session_svc = db.variants[0]
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name == "ActiveDiagnosticSession_Read");
    assert!(
        session_svc.is_some(),
        "should have service for ActiveDiagnosticSession DID"
    );

    if let Some(svc) = session_svc {
        if let Some(resp) = svc.pos_responses.first() {
            if let Some(param) = resp.params.first() {
                if let Some(diag_ir::ParamData::Value { dop, .. }) = &param.specific_data {
                    if let Some(diag_ir::DopData::NormalDop { compu_method, .. }) =
                        &dop.specific_data
                    {
                        let cm = compu_method.as_ref().unwrap();
                        assert_eq!(cm.category, diag_ir::CompuCategory::TextTable);
                    }
                }
            }
        }
    }
}

#[test]
fn test_parse_sdgs() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    let sdgs = &db.variants[0].diag_layer.sdgs;
    assert!(sdgs.is_some(), "ECM should have SDGs");
    let sdgs = sdgs.as_ref().unwrap();
    assert!(!sdgs.sdgs.is_empty(), "SDGs should not be empty");
}

#[test]
fn test_version_and_revision_are_independent() {
    let yaml = r#"
schema: "1.0"
meta:
  revision: "rev42"
  version: "2.0.0"
  author: "test"
  domain: "body"
  created: "2026-01-01"
  description: "test"
ecu:
  name: "TEST_ECU"
  id: "ECU001"
"#;
    let db = parse_yaml(yaml).unwrap();
    assert_eq!(db.revision, "rev42");
    assert_eq!(
        db.version, "2.0.0",
        "version should come from meta.version, not meta.revision"
    );
}

#[test]
fn test_parse_preserves_type_definitions() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  name: "TEST"
types:
  VehicleSpeed:
    base: u16
    bit_length: 16
  EngineState:
    base: u8
    bit_length: 8
    enum:
      OFF: 0
      RUNNING: 1
dids:
  0xF190:
    name: VIN
    type: ascii
"#;
    let db = parse_yaml(yaml).unwrap();
    assert_eq!(
        db.type_definitions.len(),
        2,
        "types section should be stored in IR"
    );
    let speed = db
        .type_definitions
        .iter()
        .find(|t| t.name == "VehicleSpeed")
        .unwrap();
    assert_eq!(speed.base, "u16");
    assert_eq!(speed.bit_length, Some(16));
    let engine = db
        .type_definitions
        .iter()
        .find(|t| t.name == "EngineState")
        .unwrap();
    assert!(
        engine.enum_values_json.is_some(),
        "enum_values_json should be populated"
    );
    let json_str = engine.enum_values_json.as_ref().unwrap();
    assert!(json_str.contains("OFF"), "should contain OFF");
    assert!(json_str.contains("RUNNING"), "should contain RUNNING");
}

#[test]
fn test_parse_comparams_flat_simple() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  name: "TEST"
comparams:
  CAN_FD_ENABLED: false
  P2_Client:
    cptype: uint16
    default: 50
    values:
      global: 50
      uds: 50
  CP_UniqueRespIdTable:
    cptype: complex
    values:
      UDS_Ethernet_DoIP: ["4096", "0", "FLXC"]
"#;
    let db = parse_yaml(yaml).unwrap();
    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let refs = &base.diag_layer.com_param_refs;

    // CAN_FD_ENABLED -> 1 ref (no protocol, simple value)
    let can_fd: Vec<_> = refs
        .iter()
        .filter(|r| {
            r.com_param
                .as_ref()
                .is_some_and(|cp| cp.short_name == "CAN_FD_ENABLED")
        })
        .collect();
    assert_eq!(can_fd.len(), 1);
    assert!(can_fd[0].simple_value.is_some());
    assert!(can_fd[0].protocol.is_none());

    // P2_Client -> 2 refs (global + uds)
    let p2: Vec<_> = refs
        .iter()
        .filter(|r| {
            r.com_param
                .as_ref()
                .is_some_and(|cp| cp.short_name == "P2_Client")
        })
        .collect();
    assert_eq!(p2.len(), 2);

    // CP_UniqueRespIdTable -> 1 ref with complex value
    let unique: Vec<_> = refs
        .iter()
        .filter(|r| {
            r.com_param
                .as_ref()
                .is_some_and(|cp| cp.short_name == "CP_UniqueRespIdTable")
        })
        .collect();
    assert_eq!(unique.len(), 1);
    assert!(unique[0].complex_value.is_some());
    assert_eq!(unique[0].complex_value.as_ref().unwrap().entries.len(), 3);
}

#[test]
fn test_parse_did_audience() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
meta:
  author: "Test"
  domain: "Test"
  created: "2026-01-01"
  revision: "0.1.0"
  description: "Audience test"
ecu:
  id: "TST"
  name: "TestECU"
types:
  u8_ident:
    base: u8
dids:
  0xF198:
    name: "RepairShopCode"
    param_name: "RepairShopCodeOrTesterSerialNumber"
    description: "Repair shop code"
    type: u8_ident
    access: public
    readable: true
    writable: false
    audience:
      afterSales: true
      development: true
"#;
    let db = parse_yaml(yaml).unwrap();
    let services = &db.variants[0].diag_layer.diag_services;
    let read_svc = services
        .iter()
        .find(|s| s.diag_comm.short_name == "RepairShopCode_Read")
        .expect("should have RepairShopCode_Read service");
    let audience = read_svc
        .diag_comm
        .audience
        .as_ref()
        .expect("service should have audience");
    assert!(audience.is_after_sales);
    assert!(audience.is_development);
    assert!(!audience.is_manufacturing);
    assert!(!audience.is_supplier);
    assert!(!audience.is_after_market);
}
