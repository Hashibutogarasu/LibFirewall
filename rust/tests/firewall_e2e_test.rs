use lib_firewall_rust::core::builder::executor::QueryExecutor;
use lib_firewall_rust::core::builder::query::{InboundRuleBuilder, OutboundRuleBuilder};
use lib_firewall_rust::core::firewall_init;
use std::ffi::CStr;

#[test]
fn test_get_inbound_rules_builder() {
    let init_result = firewall_init();
    assert!(init_result, "Failed to initialize firewall (COM)");

    let builder = InboundRuleBuilder;
    let result = QueryExecutor::execute(builder);
    let rules = result.result.0;

    println!("Found {} inbound rules", rules.len());

    if !rules.is_empty() {
        for (i, rule) in rules.iter().take(5).enumerate() {
            unsafe {
                assert!(!rule.name.is_null(), "Rule name is null");
                let name = CStr::from_ptr(rule.name).to_string_lossy();
                println!("Inbound Rule [{}]: {}", i, name);
                assert!(!name.is_empty(), "Rule name is empty");
            }
        }
    }
}

#[test]
fn test_get_outbound_rules_builder() {
    let init_result = firewall_init();
    assert!(init_result, "Failed to initialize firewall (COM)");

    let builder = OutboundRuleBuilder;
    let result = QueryExecutor::execute(builder);
    let rules = result.result.1;

    println!("Found {} outbound rules", rules.len());

    if !rules.is_empty() {
        for (i, rule) in rules.iter().take(5).enumerate() {
            unsafe {
                assert!(!rule.name.is_null(), "Rule name is null");
                let name = CStr::from_ptr(rule.name).to_string_lossy();
                println!("Outbound Rule [{}]: {}", i, name);
                assert!(!name.is_empty(), "Rule name is empty");
            }
        }
    }
}
