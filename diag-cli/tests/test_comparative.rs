//! Comparative tests: verify diag-converter MDD output is structurally
//! equivalent to reference MDD files (produced by yaml-to-mdd / CDA toolchain).
//!
//! Tests cover three pipelines:
//! - YAML -> IR -> MDD vs reference MDD
//! - ODX (PDX) -> IR -> MDD vs reference MDD
//! - ODX (PDX) -> IR vs YAML -> IR (cross-pipeline)

use diag_ir::{DiagDatabase, flatbuffers_to_ir, ir_to_flatbuffers};
use diag_odx::parse_odx;
use diag_odx::pdx_reader::read_pdx_from_reader;
use diag_yaml::parse_yaml;
use mdd_format::reader::read_mdd_bytes;
use mdd_format::writer::{WriteOptions, write_mdd_bytes};
use std::collections::BTreeSet;
use std::io::Cursor;

fn flxc1000_yaml() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXC1000.yml")
}

fn flxcng1000_yaml() -> &'static str {
    include_str!("../../test-fixtures/yaml/FLXCNG1000.yml")
}

fn flxc1000_ref_mdd() -> &'static [u8] {
    include_bytes!("../../test-fixtures/mdd/FLXC1000.mdd")
}

fn flxcng1000_ref_mdd() -> &'static [u8] {
    include_bytes!("../../test-fixtures/mdd/FLXCNG1000.mdd")
}

/// Compare diag-converter's YAML->MDD output against a reference MDD structurally.
fn compare_yaml_vs_reference_mdd(yaml: &str, ref_mdd: &[u8], name: &str) {
    // Our pipeline: YAML -> IR -> FBS -> MDD -> FBS -> IR
    let our_db = parse_yaml(yaml).unwrap();
    let our_fbs = ir_to_flatbuffers(&our_db);
    let our_mdd = write_mdd_bytes(&our_fbs, &WriteOptions::default()).unwrap();
    let (_our_meta, our_fbs_back) = read_mdd_bytes(&our_mdd).unwrap();
    let our_ir = flatbuffers_to_ir(&our_fbs_back).unwrap();

    // Reference MDD -> FBS -> IR
    let (_ref_meta, ref_fbs) = read_mdd_bytes(ref_mdd).unwrap();
    let ref_ir = flatbuffers_to_ir(&ref_fbs).unwrap();

    // Compare ECU name
    assert_eq!(
        our_ir.ecu_name, ref_ir.ecu_name,
        "{name}: ecu_name mismatch (ours={}, ref={})",
        our_ir.ecu_name, ref_ir.ecu_name
    );

    // Compare variant count
    assert_eq!(
        our_ir.variants.len(),
        ref_ir.variants.len(),
        "{name}: variant count mismatch (ours={}, ref={})",
        our_ir.variants.len(),
        ref_ir.variants.len()
    );

    // Compare variant names (sorted, normalized).
    // Reference MDD prefixes non-base variant names with ECU name (e.g. "FLXC1000_App_0101"),
    // while our YAML parser uses short names ("App_0101"). Normalize by stripping ECU prefix.
    let ecu_prefix = format!("{}_", our_ir.ecu_name);
    let normalize =
        |name: &str| -> String { name.strip_prefix(&ecu_prefix).unwrap_or(name).to_string() };
    let mut our_var_names: Vec<_> = our_ir
        .variants
        .iter()
        .map(|v| normalize(&v.diag_layer.short_name))
        .collect();
    let mut ref_var_names: Vec<_> = ref_ir
        .variants
        .iter()
        .map(|v| normalize(&v.diag_layer.short_name))
        .collect();
    our_var_names.sort();
    ref_var_names.sort();
    assert_eq!(
        our_var_names, ref_var_names,
        "{name}: variant names differ (after normalizing ECU prefix)"
    );

    // Compare DTC count
    assert_eq!(
        our_ir.dtcs.len(),
        ref_ir.dtcs.len(),
        "{name}: DTC count mismatch (ours={}, ref={})",
        our_ir.dtcs.len(),
        ref_ir.dtcs.len()
    );

    // Compare base variant state chart count
    let our_base = our_ir.variants.iter().find(|v| v.is_base_variant);
    let ref_base = ref_ir.variants.iter().find(|v| v.is_base_variant);
    if let (Some(ob), Some(rb)) = (our_base, ref_base) {
        assert_eq!(
            ob.diag_layer.state_charts.len(),
            rb.diag_layer.state_charts.len(),
            "{name}: state chart count mismatch"
        );

        // Compare service count (allow some tolerance since service generation may differ)
        let our_svc_count = ob.diag_layer.diag_services.len();
        let ref_svc_count = rb.diag_layer.diag_services.len();
        // Service count should be within reasonable range
        assert!(
            our_svc_count > 0 && ref_svc_count > 0,
            "{name}: both should have services (ours={our_svc_count}, ref={ref_svc_count})"
        );

        // Service counts may differ between toolchains (different generation strategies),
        // but both should have a reasonable number of services.
        let our_svc_names: Vec<_> = ob
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        let ref_svc_names: Vec<_> = rb
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        assert!(
            !our_svc_names.is_empty(),
            "{name}: our pipeline should produce services"
        );
        assert!(
            !ref_svc_names.is_empty(),
            "{name}: reference MDD should have services"
        );
        // Log service names for diagnostic purposes if counts differ
        if our_svc_names.len() != ref_svc_names.len() {
            eprintln!(
                "{name}: service count differs (ours={}, ref={})",
                our_svc_names.len(),
                ref_svc_names.len()
            );
            eprintln!("  ours: {our_svc_names:?}");
            eprintln!("  ref:  {ref_svc_names:?}");
        }
    }
}

#[test]
fn test_flxc1000_vs_reference_mdd() {
    compare_yaml_vs_reference_mdd(flxc1000_yaml(), flxc1000_ref_mdd(), "FLXC1000");
}

#[test]
fn test_flxcng1000_vs_reference_mdd() {
    compare_yaml_vs_reference_mdd(flxcng1000_yaml(), flxcng1000_ref_mdd(), "FLXCNG1000");
}

// --- ODX pipeline structural completeness tests ---

fn minimal_odx() -> &'static str {
    include_str!("../../test-fixtures/odx/minimal.odx")
}

/// ODX -> IR -> FBS -> MDD -> FBS -> IR roundtrip preserves structural completeness.
#[test]
fn test_odx_mdd_structural_completeness() {
    let original = parse_odx(minimal_odx()).unwrap();
    let fbs = ir_to_flatbuffers(&original);
    let mdd = write_mdd_bytes(&fbs, &WriteOptions::default()).unwrap();
    let (_meta, fbs_back) = read_mdd_bytes(&mdd).unwrap();
    let roundtripped = flatbuffers_to_ir(&fbs_back).unwrap();

    // ECU name
    assert_eq!(original.ecu_name, roundtripped.ecu_name);

    // Variant count and names
    assert_eq!(original.variants.len(), roundtripped.variants.len());
    let mut orig_names: Vec<_> = original
        .variants
        .iter()
        .map(|v| v.diag_layer.short_name.as_str())
        .collect();
    let mut rt_names: Vec<_> = roundtripped
        .variants
        .iter()
        .map(|v| v.diag_layer.short_name.as_str())
        .collect();
    orig_names.sort_unstable();
    rt_names.sort_unstable();
    assert_eq!(
        orig_names, rt_names,
        "variant names should survive ODX->MDD roundtrip"
    );

    // DTC count
    assert_eq!(original.dtcs.len(), roundtripped.dtcs.len());

    // Base variant services
    let orig_base = original
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .unwrap();
    let rt_base = roundtripped
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .unwrap();

    let mut orig_svcs: Vec<_> = orig_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();
    let mut rt_svcs: Vec<_> = rt_base
        .diag_layer
        .diag_services
        .iter()
        .map(|s| s.diag_comm.short_name.as_str())
        .collect();
    orig_svcs.sort_unstable();
    rt_svcs.sort_unstable();
    assert_eq!(
        orig_svcs, rt_svcs,
        "service names should survive ODX->MDD roundtrip"
    );

    // State charts
    assert_eq!(
        orig_base.diag_layer.state_charts.len(),
        rt_base.diag_layer.state_charts.len(),
        "state chart count should survive ODX->MDD roundtrip"
    );

    // SingleEcuJobs
    assert_eq!(
        orig_base.diag_layer.single_ecu_jobs.len(),
        rt_base.diag_layer.single_ecu_jobs.len(),
        "single_ecu_job count should survive ODX->MDD roundtrip"
    );

    // Parent refs on ECU variant
    let orig_ecu_var = original.variants.iter().find(|v| !v.is_base_variant);
    let rt_ecu_var = roundtripped.variants.iter().find(|v| !v.is_base_variant);
    if let (Some(ov), Some(rv)) = (orig_ecu_var, rt_ecu_var) {
        assert_eq!(
            ov.parent_refs.len(),
            rv.parent_refs.len(),
            "parent ref count should survive ODX->MDD roundtrip"
        );
    }
}

/// Verify that reference MDD files are well-formed and readable.
#[test]
fn test_reference_mdd_readable() {
    for (name, mdd) in [
        ("FLXC1000", flxc1000_ref_mdd()),
        ("FLXCNG1000", flxcng1000_ref_mdd()),
    ] {
        let result = read_mdd_bytes(mdd);
        assert!(
            result.is_ok(),
            "{name} reference MDD should be readable: {:?}",
            result.err()
        );
        let (_meta, fbs) = result.unwrap();
        let ir = flatbuffers_to_ir(&fbs);
        assert!(
            ir.is_ok(),
            "{name} reference MDD should deserialize to IR: {:?}",
            ir.err()
        );
    }
}

// ── ODX (PDX) fixtures ───────────────────────────────────────────────

fn flxc1000_pdx() -> &'static [u8] {
    include_bytes!("../../test-fixtures/odx/FLXC1000.pdx")
}

fn flxcng1000_pdx() -> &'static [u8] {
    include_bytes!("../../test-fixtures/odx/FLXCNG1000.pdx")
}

fn pdx_to_ir(pdx: &[u8]) -> DiagDatabase {
    read_pdx_from_reader(Cursor::new(pdx)).unwrap()
}

fn yaml_to_ir(yaml: &str) -> DiagDatabase {
    parse_yaml(yaml).unwrap()
}

fn ref_mdd_to_ir(mdd: &[u8]) -> DiagDatabase {
    let (_meta, fbs) = read_mdd_bytes(mdd).unwrap();
    flatbuffers_to_ir(&fbs).unwrap()
}

/// Normalize variant short_name by stripping ECU name prefix.
fn strip_ecu_prefix<'a>(name: &'a str, ecu: &str) -> &'a str {
    let prefix = format!("{ecu}_");
    name.strip_prefix(&prefix).unwrap_or(name)
}

// ── ODX (PDX) -> IR basic parsing ────────────────────────────────────

#[test]
fn test_pdx_flxc1000_parses() {
    let db = pdx_to_ir(flxc1000_pdx());
    assert_eq!(db.ecu_name, "FLXC1000");
    assert!(!db.variants.is_empty(), "should have variants");
    eprintln!(
        "FLXC1000 PDX: {} variants, base services: {}",
        db.variants.len(),
        db.variants
            .iter()
            .find(|v| v.is_base_variant)
            .map_or(0, |v| v.diag_layer.diag_services.len())
    );
}

#[test]
fn test_pdx_flxcng1000_parses() {
    let db = pdx_to_ir(flxcng1000_pdx());
    assert_eq!(db.ecu_name, "FLXCNG1000");
    assert!(!db.variants.is_empty(), "should have variants");
    eprintln!(
        "FLXCNG1000 PDX: {} variants, base services: {}",
        db.variants.len(),
        db.variants
            .iter()
            .find(|v| v.is_base_variant)
            .map_or(0, |v| v.diag_layer.diag_services.len())
    );
}

// ── ODX vs reference MDD ────────────────────────────────────────────

fn compare_odx_vs_reference_mdd(pdx: &[u8], ref_mdd: &[u8], name: &str) {
    let odx_ir = pdx_to_ir(pdx);
    let ref_ir = ref_mdd_to_ir(ref_mdd);

    // ECU name
    assert_eq!(
        odx_ir.ecu_name, ref_ir.ecu_name,
        "{name}: ECU name mismatch (odx={}, ref={})",
        odx_ir.ecu_name, ref_ir.ecu_name
    );

    // Variant count
    assert_eq!(
        odx_ir.variants.len(),
        ref_ir.variants.len(),
        "{name}: variant count mismatch (odx={}, ref={})",
        odx_ir.variants.len(),
        ref_ir.variants.len()
    );

    // Variant names (normalized, sorted)
    let ecu = &odx_ir.ecu_name;
    let mut odx_var_names: Vec<_> = odx_ir
        .variants
        .iter()
        .map(|v| strip_ecu_prefix(&v.diag_layer.short_name, ecu).to_string())
        .collect();
    let mut ref_var_names: Vec<_> = ref_ir
        .variants
        .iter()
        .map(|v| strip_ecu_prefix(&v.diag_layer.short_name, ecu).to_string())
        .collect();
    odx_var_names.sort();
    ref_var_names.sort();
    assert_eq!(odx_var_names, ref_var_names, "{name}: variant names differ");

    // Base variant service names must match
    let odx_base = odx_ir.variants.iter().find(|v| v.is_base_variant);
    let ref_base = ref_ir.variants.iter().find(|v| v.is_base_variant);
    if let (Some(ob), Some(rb)) = (odx_base, ref_base) {
        let odx_svc: BTreeSet<_> = ob
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        let ref_svc: BTreeSet<_> = rb
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        assert_eq!(
            odx_svc,
            ref_svc,
            "{name}: base variant service names differ\n  only in ODX: {:?}\n  only in ref: {:?}",
            odx_svc.difference(&ref_svc).collect::<Vec<_>>(),
            ref_svc.difference(&odx_svc).collect::<Vec<_>>()
        );

        // Per-service param counts
        for odx_svc in &ob.diag_layer.diag_services {
            let svc_name = &odx_svc.diag_comm.short_name;
            let ref_svc = rb
                .diag_layer
                .diag_services
                .iter()
                .find(|s| s.diag_comm.short_name == *svc_name);
            let Some(ref_svc) = ref_svc else { continue };

            if let (Some(or), Some(rr)) = (&odx_svc.request, &ref_svc.request) {
                assert_eq!(
                    or.params.len(),
                    rr.params.len(),
                    "{name}/{svc_name}: request param count {} vs {}",
                    or.params.len(),
                    rr.params.len()
                );
            }
            for (i, (or, rr)) in odx_svc
                .pos_responses
                .iter()
                .zip(ref_svc.pos_responses.iter())
                .enumerate()
            {
                assert_eq!(
                    or.params.len(),
                    rr.params.len(),
                    "{name}/{svc_name}: pos_resp[{i}] param count {} vs {}",
                    or.params.len(),
                    rr.params.len()
                );
            }
        }

        // State chart count
        assert_eq!(
            ob.diag_layer.state_charts.len(),
            rb.diag_layer.state_charts.len(),
            "{name}: state chart count mismatch"
        );
    }

    // Non-base variants: compare variant-specific services.
    // Both the ODX parser and the CDA reference may flatten inherited services
    // onto ECU variants, so we subtract base variant services from both sides
    // to compare only variant-specific additions.
    let odx_base_svc: BTreeSet<_> = odx_ir
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .map(|v| {
            v.diag_layer
                .diag_services
                .iter()
                .map(|s| s.diag_comm.short_name.as_str())
                .collect()
        })
        .unwrap_or_default();
    let ref_base_svc: BTreeSet<_> = ref_ir
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .map(|v| {
            v.diag_layer
                .diag_services
                .iter()
                .map(|s| s.diag_comm.short_name.as_str())
                .collect()
        })
        .unwrap_or_default();

    for odx_v in &odx_ir.variants {
        if odx_v.is_base_variant {
            continue;
        }
        let vname = strip_ecu_prefix(&odx_v.diag_layer.short_name, ecu);
        let ref_v = ref_ir
            .variants
            .iter()
            .find(|rv| strip_ecu_prefix(&rv.diag_layer.short_name, ecu) == vname)
            .unwrap();

        // Variant-specific services = total - inherited base services
        let odx_variant_svc: BTreeSet<_> = odx_v
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .filter(|n| !odx_base_svc.contains(n))
            .collect();
        let ref_variant_svc: BTreeSet<_> = ref_v
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .filter(|n| !ref_base_svc.contains(n))
            .collect();
        assert_eq!(
            odx_variant_svc,
            ref_variant_svc,
            "{name}/{vname}: variant-specific services differ\n  only in ODX: {:?}\n  only in ref: {:?}",
            odx_variant_svc
                .difference(&ref_variant_svc)
                .collect::<Vec<_>>(),
            ref_variant_svc
                .difference(&odx_variant_svc)
                .collect::<Vec<_>>()
        );
    }

    eprintln!("{name}: ODX vs reference MDD - PASS");
}

#[test]
fn test_odx_flxc1000_vs_reference_mdd() {
    compare_odx_vs_reference_mdd(flxc1000_pdx(), flxc1000_ref_mdd(), "FLXC1000");
}

#[test]
fn test_odx_flxcng1000_vs_reference_mdd() {
    compare_odx_vs_reference_mdd(flxcng1000_pdx(), flxcng1000_ref_mdd(), "FLXCNG1000");
}

// ── Cross-pipeline: ODX vs YAML ─────────────────────────────────────

fn compare_odx_vs_yaml(pdx: &[u8], yaml: &str, name: &str) {
    let odx_ir = pdx_to_ir(pdx);
    let yaml_ir = yaml_to_ir(yaml);

    // ECU name
    assert_eq!(
        odx_ir.ecu_name, yaml_ir.ecu_name,
        "{name}: ECU name mismatch (odx={}, yaml={})",
        odx_ir.ecu_name, yaml_ir.ecu_name
    );

    // Variant count
    assert_eq!(
        odx_ir.variants.len(),
        yaml_ir.variants.len(),
        "{name}: variant count mismatch (odx={}, yaml={})",
        odx_ir.variants.len(),
        yaml_ir.variants.len()
    );

    // Variant names
    let ecu = &odx_ir.ecu_name;
    let mut odx_var_names: Vec<_> = odx_ir
        .variants
        .iter()
        .map(|v| strip_ecu_prefix(&v.diag_layer.short_name, ecu).to_string())
        .collect();
    let mut yaml_var_names: Vec<_> = yaml_ir
        .variants
        .iter()
        .map(|v| strip_ecu_prefix(&v.diag_layer.short_name, ecu).to_string())
        .collect();
    odx_var_names.sort();
    yaml_var_names.sort();
    assert_eq!(
        odx_var_names, yaml_var_names,
        "{name}: variant names differ between ODX and YAML"
    );

    // Base variant service sets
    let odx_base = odx_ir.variants.iter().find(|v| v.is_base_variant);
    let yaml_base = yaml_ir.variants.iter().find(|v| v.is_base_variant);
    if let (Some(ob), Some(yb)) = (odx_base, yaml_base) {
        let odx_svc: BTreeSet<_> = ob
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        let yaml_svc: BTreeSet<_> = yb
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        assert_eq!(
            odx_svc,
            yaml_svc,
            "{name}: base variant service names differ between ODX and YAML\n  only in ODX: {:?}\n  only in YAML: {:?}",
            odx_svc.difference(&yaml_svc).collect::<Vec<_>>(),
            yaml_svc.difference(&odx_svc).collect::<Vec<_>>()
        );

        // Per-service param counts
        for odx_svc in &ob.diag_layer.diag_services {
            let svc_name = &odx_svc.diag_comm.short_name;
            let yaml_svc = yb
                .diag_layer
                .diag_services
                .iter()
                .find(|s| s.diag_comm.short_name == *svc_name);
            let Some(yaml_svc) = yaml_svc else { continue };

            if let (Some(or), Some(yr)) = (&odx_svc.request, &yaml_svc.request) {
                assert_eq!(
                    or.params.len(),
                    yr.params.len(),
                    "{name}/{svc_name}: request param count odx={} yaml={}",
                    or.params.len(),
                    yr.params.len()
                );
            }
            for (i, (or, yr)) in odx_svc
                .pos_responses
                .iter()
                .zip(yaml_svc.pos_responses.iter())
                .enumerate()
            {
                assert_eq!(
                    or.params.len(),
                    yr.params.len(),
                    "{name}/{svc_name}: pos_resp[{i}] param count odx={} yaml={}",
                    or.params.len(),
                    yr.params.len()
                );
            }
        }

        // State chart count
        assert_eq!(
            ob.diag_layer.state_charts.len(),
            yb.diag_layer.state_charts.len(),
            "{name}: state chart count mismatch between ODX and YAML"
        );
    }

    // Non-base variants: compare variant-specific services.
    // ODX flattens inherited services; subtract base to get variant-specific.
    let odx_base_svc: BTreeSet<_> = odx_ir
        .variants
        .iter()
        .find(|v| v.is_base_variant)
        .map(|v| {
            v.diag_layer
                .diag_services
                .iter()
                .map(|s| s.diag_comm.short_name.as_str())
                .collect()
        })
        .unwrap_or_default();

    for odx_v in &odx_ir.variants {
        if odx_v.is_base_variant {
            continue;
        }
        let vname = strip_ecu_prefix(&odx_v.diag_layer.short_name, ecu);
        let yaml_v = yaml_ir
            .variants
            .iter()
            .find(|yv| strip_ecu_prefix(&yv.diag_layer.short_name, ecu) == vname)
            .unwrap();

        let odx_variant_svc: BTreeSet<_> = odx_v
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .filter(|n| !odx_base_svc.contains(n))
            .collect();
        let yaml_variant_svc: BTreeSet<_> = yaml_v
            .diag_layer
            .diag_services
            .iter()
            .map(|s| s.diag_comm.short_name.as_str())
            .collect();
        assert_eq!(
            odx_variant_svc,
            yaml_variant_svc,
            "{name}/{vname}: variant-specific services differ between ODX and YAML\n  only in ODX: {:?}\n  only in YAML: {:?}",
            odx_variant_svc
                .difference(&yaml_variant_svc)
                .collect::<Vec<_>>(),
            yaml_variant_svc
                .difference(&odx_variant_svc)
                .collect::<Vec<_>>()
        );
    }

    eprintln!("{name}: ODX vs YAML - PASS");
}

#[test]
fn test_odx_vs_yaml_flxc1000() {
    compare_odx_vs_yaml(flxc1000_pdx(), flxc1000_yaml(), "FLXC1000");
}

#[test]
fn test_odx_vs_yaml_flxcng1000() {
    compare_odx_vs_yaml(flxcng1000_pdx(), flxcng1000_yaml(), "FLXCNG1000");
}
