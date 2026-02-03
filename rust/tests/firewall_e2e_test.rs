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
                let app_name = CStr::from_ptr(rule.application_name).to_string_lossy();
                let service_name = CStr::from_ptr(rule.service_name).to_string_lossy();
                let local_ports = CStr::from_ptr(rule.local_ports).to_string_lossy();

                println!("Inbound Rule [{}]: {}", i, name);
                println!("  App: {}", app_name);
                println!("  Service: {}", service_name);
                println!("  Protocol: {}", rule.protocol);
                println!("  Local Ports: {}", local_ports);
                println!("  Action: {:?}", rule.action);

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
                let app_name = CStr::from_ptr(rule.application_name).to_string_lossy();
                let service_name = CStr::from_ptr(rule.service_name).to_string_lossy();
                let _remote_ports = CStr::from_ptr(rule.remote_ports).to_string_lossy();

                println!("Outbound Rule [{}]: {}", i, name);
                println!("  App: {}", app_name);
                println!("  Service: {}", service_name);
                println!("  Protocol: {}", rule.protocol);
                assert!(!name.is_empty(), "Rule name is empty");
            }
        }
    }
}

#[test]

fn test_add_remove_inbound_rule() {
    use lib_firewall_rust::core::rule::adapter::{FirewallAdapter, InboundRuleCreator};

    use lib_firewall_rust::core::rule::enums::{IpProtocol, RuleAction};

    let init_result = firewall_init();

    assert!(init_result, "Failed to initialize firewall (COM)");

    let rule_name = "TestRustRule_Inbound_AutoTest";

    let _ = FirewallAdapter::delete_rule(rule_name);

    let creator = InboundRuleCreator::new(rule_name)
        .description("Created by Rust Integration Test")
        .action(RuleAction::Block)
        .local_ports("8080")
        .protocol(IpProtocol::Tcp);

    let create_result = creator.create();

    if let Err(e) = &create_result {
        println!("Error creating rule: {:?}", e);
    }
    assert!(create_result.is_ok(), "Failed to create inbound rule");

    // Verify existence
    let builder = InboundRuleBuilder;
    let result = QueryExecutor::execute(builder);
    let rules = result.result.0;

    let mut found = false;
    for rule in rules {
        unsafe {
            let name = CStr::from_ptr(rule.name).to_string_lossy();
            if name == rule_name {
                found = true;
                break;
            }
        }
    }
    assert!(found, "Rule was created but not found in query list");

    // Delete Rule
    let delete_result = FirewallAdapter::delete_rule(rule_name);
    assert!(delete_result.is_ok(), "Failed to delete inbound rule");

    // Verify deletion
    let builder_check = InboundRuleBuilder;
    let result_check = QueryExecutor::execute(builder_check);
    let rules_check = result_check.result.0;

    let mut found_after = false;
    for rule in rules_check {
        unsafe {
            let name = CStr::from_ptr(rule.name).to_string_lossy();
            if name == rule_name {
                found_after = true;
                break;
            }
        }
    }
    assert!(
        !found_after,
        "Rule was deleted but still found in query list"
    );
}
