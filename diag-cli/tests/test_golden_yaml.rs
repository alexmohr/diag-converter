use diag_ir::{flatbuffers_to_ir, ir_to_flatbuffers};
use diag_yaml::{parse_yaml, write_yaml};
use mdd_format::reader::read_mdd_bytes;
use mdd_format::writer::{WriteOptions, write_mdd_bytes};

fn flxc1000_fixture() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXC1000.yml")
}

fn flxcng1000_fixture() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXCNG1000.yml")
}

// --- FLXC1000 structural tests ---

#[test]
fn test_flxc1000_structure() {
    let db = parse_yaml(flxc1000_fixture()).unwrap();

    assert_eq!(db.ecu_name, "FLXC1000");

    // 1 base + 2 variant definitions = 3 total variants
    assert_eq!(db.variants.len(), 3);
    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let non_base: Vec<_> = db.variants.iter().filter(|v| !v.is_base_variant).collect();
    assert_eq!(non_base.len(), 2);
    assert!(
        non_base
            .iter()
            .any(|v| v.diag_layer.short_name == "FLXC1000_Boot_Variant")
    );
    assert!(
        non_base
            .iter()
            .any(|v| v.diag_layer.short_name == "FLXC1000_App_0101")
    );

    // 4 sessions
    let session_chart = base
        .diag_layer
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "Session")
        .expect("should have session state chart");
    assert_eq!(session_chart.states.len(), 4);

    // 3 security levels + Locked state
    let security_chart = base
        .diag_layer
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "SecurityAccess")
        .expect("should have security state chart");
    assert_eq!(security_chart.states.len(), 4);

    // Services: at least 3 read DIDs + generated services
    assert!(
        base.diag_layer.diag_services.len() >= 3,
        "should have at least 3 services (DIDs), got {}",
        base.diag_layer.diag_services.len()
    );
}

// --- FLXCNG1000 structural tests ---

#[test]
fn test_flxcng1000_structure() {
    let db = parse_yaml(flxcng1000_fixture()).unwrap();

    assert_eq!(db.ecu_name, "FLXCNG1000");

    // 1 base + 1 variant definition = 2 total variants
    assert_eq!(db.variants.len(), 2);
    let non_base: Vec<_> = db.variants.iter().filter(|v| !v.is_base_variant).collect();
    assert_eq!(non_base.len(), 1);
    assert_eq!(non_base[0].diag_layer.short_name, "FLXCNG1000_App_1010");

    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();

    // 4 sessions
    let session_chart = base
        .diag_layer
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "Session")
        .expect("should have session state chart");
    assert_eq!(session_chart.states.len(), 4);

    // 2 security levels + Locked state
    let security_chart = base
        .diag_layer
        .state_charts
        .iter()
        .find(|sc| sc.short_name == "SecurityAccess")
        .expect("should have security state chart");
    assert_eq!(security_chart.states.len(), 3);

    // securityAccess is disabled - verify no SecurityAccess services generated
    let sec_services: Vec<_> = base
        .diag_layer
        .diag_services
        .iter()
        .filter(|s| s.diag_comm.semantic == "SECURITY-ACCESS")
        .collect();
    assert!(
        sec_services.is_empty(),
        "securityAccess disabled, should have no SecurityAccess services"
    );
}

// --- YAML -> IR -> YAML roundtrip ---

fn assert_roundtrip(yaml: &str, name: &str) {
    let db = parse_yaml(yaml).unwrap();
    let yaml_out = write_yaml(&db).unwrap();
    let db2 = parse_yaml(&yaml_out).unwrap();

    assert_eq!(db.ecu_name, db2.ecu_name, "{name}: ecu_name mismatch");
    assert_eq!(
        db.variants.len(),
        db2.variants.len(),
        "{name}: variant count mismatch"
    );
    assert_eq!(db.dtcs.len(), db2.dtcs.len(), "{name}: DTC count mismatch");

    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let base2 = db2.variants.iter().find(|v| v.is_base_variant).unwrap();
    assert_eq!(
        base.diag_layer.state_charts.len(),
        base2.diag_layer.state_charts.len(),
        "{name}: state chart count mismatch"
    );
}

#[test]
fn test_flxc1000_yaml_roundtrip() {
    assert_roundtrip(flxc1000_fixture(), "FLXC1000");
}

#[test]
fn test_flxcng1000_yaml_roundtrip() {
    assert_roundtrip(flxcng1000_fixture(), "FLXCNG1000");
}

// --- YAML -> MDD -> IR structural comparison ---

fn assert_mdd_roundtrip(yaml: &str, name: &str) {
    let db = parse_yaml(yaml).unwrap();
    let fbs = ir_to_flatbuffers(&db);
    let mdd = write_mdd_bytes(&fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs_back) = read_mdd_bytes(&mdd).unwrap();
    let db2 = flatbuffers_to_ir(&fbs_back).unwrap();

    assert_eq!(
        db.ecu_name, db2.ecu_name,
        "{name}: ecu_name mismatch after MDD roundtrip"
    );
    assert_eq!(
        db.variants.len(),
        db2.variants.len(),
        "{name}: variant count mismatch"
    );
    assert_eq!(db.dtcs.len(), db2.dtcs.len(), "{name}: DTC count mismatch");

    // Compare service names (sorted) on base variant
    let base = db.variants.iter().find(|v| v.is_base_variant).unwrap();
    let base2 = db2.variants.iter().find(|v| v.is_base_variant).unwrap();

    let mut names1: Vec<_> = base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();
    let mut names2: Vec<_> = base2
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();
    names1.sort_unstable();
    names2.sort_unstable();
    assert_eq!(
        names1, names2,
        "{name}: service names differ after MDD roundtrip"
    );

    // Compare variant names
    let mut var_names1: Vec<_> = db
        .variants
        .iter()
        .map(|v| v.diag_layer.short_name.as_str())
        .collect();
    let mut var_names2: Vec<_> = db2
        .variants
        .iter()
        .map(|v| v.diag_layer.short_name.as_str())
        .collect();
    var_names1.sort_unstable();
    var_names2.sort_unstable();
    assert_eq!(
        var_names1, var_names2,
        "{name}: variant names differ after MDD roundtrip"
    );
}

#[test]
fn test_flxc1000_mdd_roundtrip() {
    assert_mdd_roundtrip(flxc1000_fixture(), "FLXC1000");
}

#[test]
fn test_flxcng1000_mdd_roundtrip() {
    assert_mdd_roundtrip(flxcng1000_fixture(), "FLXCNG1000");
}
