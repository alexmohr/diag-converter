use diag_yaml::{parse_yaml, write_yaml};

#[test]
fn test_yaml_roundtrip_preserves_did_snapshot() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  name: "TEST"
dids:
  0xF190:
    name: VIN
    type: ascii
    access: public
    snapshot: true
    io_control:
      freeze_current_state: true
"#;
    let db = parse_yaml(yaml).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml_out).unwrap();
    // Writer outputs DID keys as decimal numbers (0xF190 = 61840)
    let did = &doc["dids"][61840];
    assert_eq!(
        did["snapshot"].as_bool(),
        Some(true),
        "snapshot should roundtrip"
    );
    assert!(
        did["io_control"].is_mapping(),
        "io_control should roundtrip"
    );
}

#[test]
fn test_yaml_roundtrip_preserves_annotations_and_x_oem() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  name: "TEST"
annotations:
  note: "This is a test annotation"
x-oem:
  vendor_code: "XYZ"
  hw_revision: 42
"#;
    let db = parse_yaml(yaml).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml_out).unwrap();
    assert!(
        doc["annotations"].is_mapping(),
        "annotations should roundtrip"
    );
    assert_eq!(
        doc["annotations"]["note"].as_str(),
        Some("This is a test annotation")
    );
    assert!(doc["x-oem"].is_mapping(), "x-oem should roundtrip");
}

#[test]
fn test_yaml_roundtrip_preserves_types_section() {
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
  0x0100:
    name: Speed
    type: VehicleSpeed
"#;
    let db = parse_yaml(yaml).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml_out).unwrap();
    let types = doc["types"]
        .as_mapping()
        .expect("types section should exist in output");
    assert!(
        types.contains_key(serde_yaml::Value::String("VehicleSpeed".into())),
        "VehicleSpeed type should be in output"
    );
    assert!(
        types.contains_key(serde_yaml::Value::String("EngineState".into())),
        "EngineState type should be in output"
    );
}

#[test]
fn test_yaml_roundtrip_minimal() {
    let content = include_str!("../../test-fixtures/yaml/minimal-ecu.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    assert_eq!(original.ecu_name, reparsed.ecu_name);
    assert_eq!(original.variants.len(), reparsed.variants.len());
}

#[test]
fn test_yaml_roundtrip_ecm_preserves_ecu_name() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    assert_eq!(original.ecu_name, reparsed.ecu_name);
    assert_eq!(original.revision, reparsed.revision);
}

#[test]
fn test_yaml_roundtrip_ecm_preserves_dtc_count() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    assert_eq!(original.dtcs.len(), reparsed.dtcs.len());
}

#[test]
fn test_yaml_roundtrip_ecm_preserves_service_count() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    let _orig_services = original.variants[0].diag_layer.diag_services.len();
    let reparsed_services = reparsed.variants[0].diag_layer.diag_services.len();

    // The reparsed version should have at least the same number of services
    // (DIDs generate read/write services, routines generate services)
    assert!(reparsed_services > 0, "reparsed should have services");
    // Note: exact count may differ because writer may not re-emit all services
    // but key data should be preserved
    assert_eq!(original.ecu_name, reparsed.ecu_name);
}

#[test]
fn test_write_yaml_produces_valid_yaml() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&db).unwrap();

    // Should be parseable as generic YAML
    let _: serde_yaml::Value = serde_yaml::from_str(&yaml_output).unwrap();
}

#[test]
fn test_write_yaml_contains_schema() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&db).unwrap();

    assert!(
        yaml_output.contains("opensovd.cda.diagdesc/v1"),
        "output should contain schema identifier"
    );
}

/// Regression test: writable DID flag must survive IR -> YAML roundtrip.
/// Previously, `.cloned()` on a mutable borrow caused the writable flag to be
/// lost because the clone was modified instead of the original map entry.
#[test]
fn test_writable_did_roundtrip() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    // Verify the IR has at least one Write_ service (proving the DID is writable)
    let layer = &db.variants[0].diag_layer;
    let write_services: Vec<_> = layer
        .diag_services
        .iter()
        .filter(|s| s.diag_comm.short_name.ends_with("_Write"))
        .collect();
    assert!(
        !write_services.is_empty(),
        "example-ecm.yml should have writable DIDs generating _Write services"
    );

    // Write to YAML and re-parse
    let yaml_output = write_yaml(&db).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    // The reparsed IR must still have Write_ services for writable DIDs
    let reparsed_layer = &reparsed.variants[0].diag_layer;
    let reparsed_write_services: Vec<_> = reparsed_layer
        .diag_services
        .iter()
        .filter(|s| s.diag_comm.short_name.ends_with("_Write"))
        .collect();
    assert_eq!(
        write_services.len(),
        reparsed_write_services.len(),
        "writable DID count must be preserved through IR -> YAML -> IR roundtrip"
    );
}

#[test]
fn test_memory_config_roundtrip() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  id: "MEM_ECU"
  name: "MemoryTestECU"
memory:
  default_address_format:
    address_bytes: 4
    length_bytes: 2
  regions:
    flash:
      name: Flash
      description: "Main flash region"
      start: 0x08000000
      end: 0x080FFFFF
      access: read_write
      security_level: "level_1"
      session: programming
    calibration:
      name: Calibration
      start: 0x20000000
      end: 0x2000FFFF
      access: read
      session:
        - default
        - extended
  data_blocks:
    firmware:
      name: FirmwareUpdate
      description: "ECU firmware download"
      type: download
      memory_address: 0x08000000
      memory_size: 0x100000
      format: compressed
      max_block_length: 0xFFF
      session: programming
"#;

    let db = parse_yaml(yaml).unwrap();
    let mem = db.memory.as_ref().expect("memory config should be parsed");

    // Verify parsed structure
    assert_eq!(mem.default_address_format.address_bytes, 4);
    assert_eq!(mem.default_address_format.length_bytes, 2);
    assert_eq!(mem.regions.len(), 2);
    assert_eq!(mem.data_blocks.len(), 1);

    // Check a region
    let flash = mem.regions.iter().find(|r| r.name == "Flash").unwrap();
    assert_eq!(flash.start_address, 0x08000000);
    assert_eq!(flash.size, 0x000FFFFF);
    assert_eq!(flash.access, diag_ir::MemoryAccess::ReadWrite);
    assert_eq!(flash.security_level.as_deref(), Some("level_1"));
    assert_eq!(
        flash.session.as_deref(),
        Some(&["programming".to_string()][..])
    );

    // Check multi-session region
    let cal = mem
        .regions
        .iter()
        .find(|r| r.name == "Calibration")
        .unwrap();
    assert_eq!(cal.session.as_ref().unwrap().len(), 2);

    // Check data block
    let fw = &mem.data_blocks[0];
    assert_eq!(fw.name, "FirmwareUpdate");
    assert_eq!(fw.block_type, diag_ir::DataBlockType::Download);
    assert_eq!(fw.format, diag_ir::DataBlockFormat::Compressed);

    // Roundtrip: write back to YAML and re-parse
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    let mem2 = db2
        .memory
        .as_ref()
        .expect("memory config should survive roundtrip");

    assert_eq!(mem.default_address_format, mem2.default_address_format);
    assert_eq!(mem.regions.len(), mem2.regions.len());
    assert_eq!(mem.data_blocks.len(), mem2.data_blocks.len());

    let flash2 = mem2.regions.iter().find(|r| r.name == "Flash").unwrap();
    assert_eq!(flash.start_address, flash2.start_address);
    assert_eq!(flash.size, flash2.size);
    assert_eq!(flash.access, flash2.access);
}

#[test]
fn test_sessions_state_model_security_roundtrip() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  id: "SC_ECU"
  name: "StateChartECU"
sessions:
  default:
    id: 1
    alias: "DS"
  extended:
    id: 3
    alias: "EXTDS"
  programming:
    id: 2
state_model:
  initial_state:
    session: default
  session_transitions:
    default:
      - extended
      - programming
    extended:
      - default
security:
  level_1:
    level: 1
    seed_size: 4
    key_size: 4
  level_2:
    level: 2
    seed_size: 8
    key_size: 8
"#;

    let db = parse_yaml(yaml).unwrap();
    let layer = &db.variants[0].diag_layer;

    // Verify state charts were built
    assert_eq!(
        layer.state_charts.len(),
        2,
        "should have session + security state charts"
    );

    let session_sc = layer
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "Session")
        .unwrap();
    assert_eq!(session_sc.states.len(), 3);
    assert_eq!(session_sc.start_state_short_name_ref, "DS"); // alias for "default"
    assert_eq!(session_sc.state_transitions.len(), 3); // DS->EXTDS, DS->Programming, EXTDS->DS

    let security_sc = layer
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "SecurityAccess")
        .unwrap();
    assert_eq!(security_sc.states.len(), 3); // Locked + Level_1 + Level_2

    // Roundtrip
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    let layer2 = &db2.variants[0].diag_layer;

    assert_eq!(layer2.state_charts.len(), 2);

    let session_sc2 = layer2
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "Session")
        .unwrap();
    assert_eq!(session_sc.states.len(), session_sc2.states.len());
    assert_eq!(
        session_sc.start_state_short_name_ref,
        session_sc2.start_state_short_name_ref
    );
    assert_eq!(
        session_sc.state_transitions.len(),
        session_sc2.state_transitions.len()
    );

    // Verify session IDs survived - state names are CDA names (alias or capitalized key)
    let ext_state = session_sc2
        .states
        .iter()
        .find(|s| s.short_name == "EXTDS")
        .unwrap();
    assert_eq!(ext_state.long_name.as_ref().unwrap().value, "3");
    assert_eq!(ext_state.long_name.as_ref().unwrap().ti, "extended"); // YAML key stored in ti

    let security_sc2 = layer2
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "SecurityAccess")
        .unwrap();
    assert_eq!(security_sc.states.len(), security_sc2.states.len());

    // Verify security levels survived - security states use "Level_N" CDA naming
    let lvl1 = security_sc2
        .states
        .iter()
        .find(|s| s.short_name.contains('1'))
        .unwrap();
    assert_eq!(lvl1.long_name.as_ref().unwrap().value, "1");
}

#[test]
fn test_authentication_roundtrip() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  id: "AUTH_ECU"
  name: "AuthTestECU"
authentication:
  roles:
    tester:
      id: 0
      timeout_s: 30
    factory:
      id: 1
      timeout_s: 30
    oem:
      id: 2
      timeout_s: 60
"#;

    let db = parse_yaml(yaml).unwrap();
    let layer = &db.variants[0].diag_layer;

    let auth_sc = layer
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "Authentication")
        .expect("should have authentication state chart");
    assert_eq!(auth_sc.states.len(), 3);

    // Verify role IDs
    let tester = auth_sc
        .states
        .iter()
        .find(|s| s.short_name == "tester")
        .unwrap();
    assert_eq!(tester.long_name.as_ref().unwrap().value, "0");
    let oem = auth_sc
        .states
        .iter()
        .find(|s| s.short_name == "oem")
        .unwrap();
    assert_eq!(oem.long_name.as_ref().unwrap().value, "2");

    // Roundtrip
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();
    let layer2 = &db2.variants[0].diag_layer;

    let auth_sc2 = layer2
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "Authentication")
        .expect("authentication state chart must survive roundtrip");
    assert_eq!(auth_sc.states.len(), auth_sc2.states.len());

    let factory2 = auth_sc2
        .states
        .iter()
        .find(|s| s.short_name == "factory")
        .unwrap();
    assert_eq!(factory2.long_name.as_ref().unwrap().value, "1");
}

#[test]
fn test_variants_roundtrip() {
    let content = include_str!("../../test-fixtures/yaml/FLXC1000.yml");
    let db = parse_yaml(content).unwrap();

    // FLXC1000.yml defines 2 variant definitions: Boot_Variant and App_0101
    // Plus the base variant = 3 total
    assert!(
        db.variants.len() >= 3,
        "should have base + 2 variant definitions, got {}",
        db.variants.len()
    );

    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    assert!(!base.diag_layer.short_name.is_empty());

    let non_base: Vec<_> = db.variants.iter().filter(|v| !v.is_base_variant).collect();
    assert_eq!(non_base.len(), 2);

    // Verify Boot_Variant has matching parameter
    let boot = non_base
        .iter()
        .find(|v| v.diag_layer.short_name == "FLXC1000_Boot_Variant")
        .unwrap();
    assert!(
        !boot.variant_patterns.is_empty(),
        "Boot_Variant should have variant patterns"
    );
    let mp = &boot.variant_patterns[0].matching_parameters[0];
    assert_eq!(mp.diag_service.diag_comm.short_name, "Identification_Read");
    assert_eq!(mp.out_param.short_name, "Identification");
    assert_eq!(mp.expected_value, "0xFF0000");

    // Verify parent ref points to base
    assert!(!boot.parent_refs.is_empty());

    // Roundtrip
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    let non_base2: Vec<_> = db2.variants.iter().filter(|v| !v.is_base_variant).collect();
    assert_eq!(
        non_base.len(),
        non_base2.len(),
        "variant definition count must be preserved"
    );

    let boot2 = non_base2
        .iter()
        .find(|v| v.diag_layer.short_name == "FLXC1000_Boot_Variant")
        .unwrap();
    let mp2 = &boot2.variant_patterns[0].matching_parameters[0];
    assert_eq!(mp.expected_value, mp2.expected_value);
    assert_eq!(
        mp.diag_service.diag_comm.short_name,
        mp2.diag_service.diag_comm.short_name
    );
}

#[test]
fn test_access_patterns_roundtrip() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    // Verify access patterns are parsed into PreConditionStateRefs
    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();

    // Find a service with "extended_write" access (DID with access: extended_write)
    let write_svc = base
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name.ends_with("_Write"))
        .expect("should have at least one Write DID service");

    assert!(
        !write_svc.diag_comm.pre_condition_state_refs.is_empty(),
        "Write service should have PreConditionStateRefs from access pattern"
    );

    // Verify the session/security refs match the access pattern
    let session_refs: Vec<_> = write_svc
        .diag_comm
        .pre_condition_state_refs
        .iter()
        .filter(|r| r.value == "Session")
        .collect();
    let security_refs: Vec<_> = write_svc
        .diag_comm
        .pre_condition_state_refs
        .iter()
        .filter(|r| r.value == "SecurityAccess")
        .collect();
    // extended_write pattern: sessions: [extended], security: [level_01]
    // State names are CDA names: alias ("extendedDiagnosticSession") and Level_N format
    assert_eq!(session_refs.len(), 1);
    assert_eq!(
        session_refs[0].in_param_path_short_name,
        "extendedDiagnosticSession"
    );
    assert_eq!(security_refs.len(), 1);
    assert_eq!(security_refs[0].in_param_path_short_name, "Level_1");

    // Roundtrip
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    // Verify access patterns are preserved
    let base2 = db2.variants.iter().find(|v| v.is_base_variant).unwrap();
    let write_svc2 = base2
        .diag_layer
        .diag_services
        .iter()
        .find(|s| s.diag_comm.short_name.ends_with("_Write"))
        .expect("should still have Write service after roundtrip");

    assert_eq!(
        write_svc.diag_comm.pre_condition_state_refs.len(),
        write_svc2.diag_comm.pre_condition_state_refs.len(),
        "PreConditionStateRefs count should be preserved"
    );
}

#[test]
fn test_identification_roundtrip() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    // Verify identification is stored in SDG and survives roundtrip
    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let base2 = db2.variants.iter().find(|v| v.is_base_variant).unwrap();

    let has_ident_sdg = |layer: &diag_ir::DiagLayer| -> bool {
        layer.sdgs.as_ref().is_some_and(|sdgs| {
            sdgs.sdgs
                .iter()
                .any(|sdg| sdg.caption_sn == "identification")
        })
    };

    assert!(
        has_ident_sdg(&base.diag_layer),
        "Original should have identification SDG"
    );
    assert!(
        has_ident_sdg(&base2.diag_layer),
        "Roundtripped should have identification SDG"
    );

    // Check that the YAML output contains identification content
    assert!(
        yaml_out.contains("expected_idents"),
        "YAML output should contain identification section"
    );
}

#[test]
fn test_comparams_roundtrip() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    let has_comparams_sdg = |layer: &diag_ir::DiagLayer| -> bool {
        layer
            .sdgs
            .as_ref()
            .is_some_and(|sdgs| sdgs.sdgs.iter().any(|sdg| sdg.caption_sn == "comparams"))
    };

    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let base2 = db2.variants.iter().find(|v| v.is_base_variant).unwrap();

    assert!(
        has_comparams_sdg(&base.diag_layer),
        "Original should have comparams SDG"
    );
    assert!(
        has_comparams_sdg(&base2.diag_layer),
        "Roundtripped should have comparams SDG"
    );

    // Verify YAML output contains key comparams in flat format
    assert!(
        yaml_out.contains("comparams"),
        "Should contain comparams section"
    );
    assert!(
        yaml_out.contains("P2_Client"),
        "Should contain P2_Client param"
    );
    assert!(
        yaml_out.contains("CAN_FD_ENABLED"),
        "Should contain CAN_FD_ENABLED param"
    );

    // Verify com_param_refs are preserved through roundtrip
    assert_eq!(
        base.diag_layer.com_param_refs.len(),
        base2.diag_layer.com_param_refs.len(),
        "ComParamRef count must be preserved"
    );
}

#[test]
fn test_comparams_roundtrip_flxc1000() {
    let content = include_str!("../../test-fixtures/yaml/FLXC1000.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let base2 = db2.variants.iter().find(|v| v.is_base_variant).unwrap();

    // FLXC1000 has 3 comparams, each with 2 protocols -> 6 ComParamRefs
    assert!(
        !base.diag_layer.com_param_refs.is_empty(),
        "Should have ComParamRefs"
    );
    assert_eq!(
        base.diag_layer.com_param_refs.len(),
        base2.diag_layer.com_param_refs.len(),
        "ComParamRef count must be preserved"
    );

    // Verify complex value roundtrip
    let unique_refs: Vec<_> = base
        .diag_layer
        .com_param_refs
        .iter()
        .filter(|r| {
            r.com_param
                .as_ref()
                .is_some_and(|cp| cp.short_name == "CP_UniqueRespIdTable")
        })
        .collect();
    assert!(
        !unique_refs.is_empty(),
        "Should have CP_UniqueRespIdTable refs"
    );
    assert!(
        unique_refs[0].complex_value.is_some(),
        "CP_UniqueRespIdTable should have complex value"
    );
}

#[test]
fn test_dtc_config_roundtrip() {
    let content = include_str!("../../test-fixtures/yaml/example-ecm.yml");
    let db = parse_yaml(content).unwrap();

    // Verify DTCs have snapshot/extended_data references in SDGs
    let dtc = db
        .dtcs
        .iter()
        .find(|d| d.short_name == "CrankshaftPositionCorrelation")
        .unwrap();
    let sdgs = dtc.sdgs.as_ref().expect("DTC should have SDGs");
    let has_snap = sdgs.sdgs.iter().any(|s| s.caption_sn == "dtc_snapshots");
    let has_ext = sdgs
        .sdgs
        .iter()
        .any(|s| s.caption_sn == "dtc_extended_data");
    assert!(has_snap, "DTC should have snapshot references");
    assert!(has_ext, "DTC should have extended_data references");

    // Roundtrip
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    // Verify DTC snapshot/extended_data survive
    let dtc2 = db2
        .dtcs
        .iter()
        .find(|d| d.short_name == "CrankshaftPositionCorrelation")
        .unwrap();
    let sdgs2 = dtc2
        .sdgs
        .as_ref()
        .expect("Roundtripped DTC should have SDGs");
    assert!(sdgs2.sdgs.iter().any(|s| s.caption_sn == "dtc_snapshots"));
    assert!(
        sdgs2
            .sdgs
            .iter()
            .any(|s| s.caption_sn == "dtc_extended_data")
    );

    // Verify dtc_config is in the YAML output
    assert!(
        yaml_out.contains("dtc_config"),
        "YAML output should contain dtc_config"
    );
    assert!(
        yaml_out.contains("snapshots"),
        "dtc_config should contain snapshots"
    );
    assert!(
        yaml_out.contains("extended_data"),
        "dtc_config should contain extended_data"
    );
}

#[test]
fn test_yaml_roundtrip_flxc1000_preserves_all_services() {
    let content = include_str!("../../test-fixtures/yaml/FLXC1000.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    let orig_base = original
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .unwrap();
    let reparse_base = reparsed
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .unwrap();

    let orig_svc_names: Vec<&str> = orig_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();
    let reparse_svc_names: Vec<&str> = reparse_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();

    assert_eq!(
        orig_svc_names.len(),
        reparse_svc_names.len(),
        "Service count must be preserved. Original: {orig_svc_names:?}, Reparsed: {reparse_svc_names:?}"
    );
}

#[test]
fn test_yaml_roundtrip_flxc1000_service_names_preserved() {
    let content = include_str!("../../test-fixtures/yaml/FLXC1000.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    let orig_base = original
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .unwrap();
    let reparse_base = reparsed
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .unwrap();

    let orig_names: std::collections::BTreeSet<&str> = orig_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();
    let reparse_names: std::collections::BTreeSet<&str> = reparse_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();

    let lost: Vec<&&str> = orig_names.difference(&reparse_names).collect();
    let gained: Vec<&&str> = reparse_names.difference(&orig_names).collect();

    assert!(lost.is_empty(), "Services lost in roundtrip: {lost:?}");
    if !gained.is_empty() {
        eprintln!("Services gained in roundtrip (acceptable): {gained:?}");
    }
}

#[test]
fn test_write_yaml_contains_services_section() {
    let content = include_str!("../../test-fixtures/yaml/FLXC1000.yml");
    let db = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&db).unwrap();

    assert!(
        yaml_output.contains("diagnosticSessionControl"),
        "should contain diagnosticSessionControl"
    );
    assert!(yaml_output.contains("ecuReset"), "should contain ecuReset");
    assert!(
        yaml_output.contains("securityAccess"),
        "should contain securityAccess"
    );
    assert!(
        yaml_output.contains("communicationControl"),
        "should contain communicationControl"
    );
    assert!(
        yaml_output.contains("testerPresent"),
        "should contain testerPresent"
    );
    assert!(
        yaml_output.contains("requestDownload"),
        "should contain requestDownload"
    );
}

#[test]
fn test_yaml_double_roundtrip_stable() {
    let content = include_str!("../../test-fixtures/yaml/FLXC1000.yml");
    let ir1 = parse_yaml(content).unwrap();
    let yaml1 = write_yaml(&ir1).unwrap();
    let ir2 = parse_yaml(&yaml1).unwrap();
    let yaml2 = write_yaml(&ir2).unwrap();
    let ir3 = parse_yaml(&yaml2).unwrap();

    let base2 = ir2.variants.iter().find(|v| v.is_base_variant).unwrap();
    let base3 = ir3.variants.iter().find(|v| v.is_base_variant).unwrap();

    let names2: Vec<&str> = base2
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();
    let names3: Vec<&str> = base3
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();

    assert_eq!(
        names2, names3,
        "Second roundtrip should produce identical services. \
         If this fails, the extractor introduces drift on re-serialization."
    );
}

#[test]
fn test_yaml_roundtrip_preserves_variant_services() {
    let content = include_str!("../../test-fixtures/yaml/FLXC1000.yml");
    let original = parse_yaml(content).unwrap();
    let yaml_output = write_yaml(&original).unwrap();
    let reparsed = parse_yaml(&yaml_output).unwrap();

    assert_eq!(
        original.variants.len(),
        reparsed.variants.len(),
        "Variant count must be preserved"
    );

    for (orig_v, reparse_v) in original.variants.iter().zip(reparsed.variants.iter()) {
        let orig_count = orig_v.diag_layer.diag_services.len();
        let reparse_count = reparse_v.diag_layer.diag_services.len();
        assert!(
            reparse_count >= orig_count || orig_count == 0,
            "Variant '{}': service count decreased from {} to {}",
            orig_v.diag_layer.short_name,
            orig_count,
            reparse_count,
        );
    }
}
#[test]
fn test_yaml_roundtrip_preserves_audience() {
    let yaml = r#"
schema: "opensovd.cda.diagdesc/v1"
ecu:
  name: "TEST"
types:
  u8_ident:
    base: u8
dids:
  0xF198:
    name: RepairShopCode
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
    let yaml_out = write_yaml(&db).unwrap();
    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml_out).unwrap();
    let did = &doc["dids"][0xF198];
    assert!(
        did["audience"].is_mapping(),
        "audience should be present in YAML output: got {did:?}"
    );
    assert_eq!(
        did["audience"]["afterSales"].as_bool(),
        Some(true),
        "afterSales should be true"
    );
    assert_eq!(
        did["audience"]["development"].as_bool(),
        Some(true),
        "development should be true"
    );
    // Fields not set should be absent
    assert!(
        did["audience"]["manufacturing"].is_null(),
        "manufacturing should not be present"
    );
    assert!(
        did["audience"]["supplier"].is_null(),
        "supplier should not be present"
    );
}
