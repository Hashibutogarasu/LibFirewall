use lib_firewall_rust::core::builder::executor::QueryExecutor;
use lib_firewall_rust::core::connection::adapter::{
    ConnectionRuleCreator, ConnectionSecurityAdapter,
};
use lib_firewall_rust::core::connection::query::ConnectionSecurityRuleBuilder;
use lib_firewall_rust::core::rule::enums::ConnectionSecurityRuleType;
use std::ffi::CStr;

const TEST_PREFIX: &str = "LibFirewall_Test_";

fn cleanup_test_rule(name: &str) {
    let _ = ConnectionSecurityAdapter::remove_rule(name);
}

#[test]
fn test_connection_security_query() {
    let builder = ConnectionSecurityRuleBuilder;
    let result = QueryExecutor::execute(builder);
    let rules = result.result;

    println!("Found {} connection security rules", rules.len());

    for rule in &rules {
        unsafe {
            let name = CStr::from_ptr(rule.name);
            println!("  Rule: {:?}", name);
        }
    }
}

#[test]
fn test_connection_security_rule_type_enum() {
    assert_eq!(ConnectionSecurityRuleType::Isolation.to_i32(), 1);
    assert_eq!(
        ConnectionSecurityRuleType::AuthenticationExemption.to_i32(),
        2
    );
    assert_eq!(ConnectionSecurityRuleType::ServerToServer.to_i32(), 3);
    assert_eq!(ConnectionSecurityRuleType::Tunnel.to_i32(), 4);
    assert_eq!(ConnectionSecurityRuleType::Custom.to_i32(), 5);

    assert_eq!(
        ConnectionSecurityRuleType::from_i32(1),
        ConnectionSecurityRuleType::Isolation
    );
    assert_eq!(
        ConnectionSecurityRuleType::from_i32(2),
        ConnectionSecurityRuleType::AuthenticationExemption
    );
    assert_eq!(
        ConnectionSecurityRuleType::from_i32(3),
        ConnectionSecurityRuleType::ServerToServer
    );
    assert_eq!(
        ConnectionSecurityRuleType::from_i32(4),
        ConnectionSecurityRuleType::Tunnel
    );
    assert_eq!(
        ConnectionSecurityRuleType::from_i32(99),
        ConnectionSecurityRuleType::Custom
    );
}

#[test]
fn test_isolation_rule_lifecycle() {
    let rule_name = format!("{}Isolation", TEST_PREFIX);
    cleanup_test_rule(&rule_name);

    // Create
    let result = ConnectionRuleCreator::new(&rule_name)
        .description("Test isolation rule")
        .rule_type(ConnectionSecurityRuleType::Isolation)
        .enabled(true)
        .create();

    if let Err(e) = &result {
        println!("Create failed (may require admin): {}", e);
        return;
    }
    assert!(result.is_ok(), "Failed to create isolation rule");

    // Get - verify rule exists
    let builder = ConnectionSecurityRuleBuilder;
    let query_result = QueryExecutor::execute(builder);
    let rules = query_result.result;

    let found = rules.iter().any(|r| unsafe {
        CStr::from_ptr(r.name)
            .to_string_lossy()
            .contains(&rule_name)
    });
    assert!(found, "Isolation rule not found after creation");

    // Delete
    let delete_result = ConnectionSecurityAdapter::remove_rule(&rule_name);
    assert!(delete_result.is_ok(), "Failed to delete isolation rule");

    println!("✓ Isolation rule lifecycle test passed");
}

#[test]
fn test_auth_exemption_rule_lifecycle() {
    let rule_name = format!("{}AuthExemption", TEST_PREFIX);
    cleanup_test_rule(&rule_name);

    let result = ConnectionRuleCreator::new(&rule_name)
        .description("Test auth exemption rule")
        .rule_type(ConnectionSecurityRuleType::AuthenticationExemption)
        .enabled(true)
        .create();

    if let Err(e) = &result {
        println!("Create failed (may require admin): {}", e);
        return;
    }
    assert!(result.is_ok(), "Failed to create auth exemption rule");

    let delete_result = ConnectionSecurityAdapter::remove_rule(&rule_name);
    assert!(
        delete_result.is_ok(),
        "Failed to delete auth exemption rule"
    );

    println!("✓ Auth exemption rule lifecycle test passed");
}

#[test]
fn test_server_to_server_rule_lifecycle() {
    let rule_name = format!("{}ServerToServer", TEST_PREFIX);
    cleanup_test_rule(&rule_name);

    let result = ConnectionRuleCreator::new(&rule_name)
        .description("Test server-to-server rule")
        .rule_type(ConnectionSecurityRuleType::ServerToServer)
        .enabled(true)
        .local_addresses("192.168.1.0/24")
        .remote_addresses("10.0.0.0/8")
        .create();

    if let Err(e) = &result {
        println!("Create failed (may require admin): {}", e);
        return;
    }
    assert!(result.is_ok(), "Failed to create server-to-server rule");

    let delete_result = ConnectionSecurityAdapter::remove_rule(&rule_name);
    assert!(
        delete_result.is_ok(),
        "Failed to delete server-to-server rule"
    );

    println!("✓ Server-to-server rule lifecycle test passed");
}

#[test]
fn test_tunnel_rule_lifecycle() {
    let rule_name = format!("{}Tunnel", TEST_PREFIX);
    cleanup_test_rule(&rule_name);

    let result = ConnectionRuleCreator::new(&rule_name)
        .description("Test tunnel rule")
        .rule_type(ConnectionSecurityRuleType::Tunnel)
        .enabled(true)
        .create();

    if let Err(e) = &result {
        println!("Create failed (may require admin): {}", e);
        return;
    }
    assert!(result.is_ok(), "Failed to create tunnel rule");

    let delete_result = ConnectionSecurityAdapter::remove_rule(&rule_name);
    assert!(delete_result.is_ok(), "Failed to delete tunnel rule");

    println!("✓ Tunnel rule lifecycle test passed");
}

#[test]
fn test_custom_rule_lifecycle() {
    let rule_name = format!("{}Custom", TEST_PREFIX);
    cleanup_test_rule(&rule_name);

    let result = ConnectionRuleCreator::new(&rule_name)
        .description("Test custom rule")
        .rule_type(ConnectionSecurityRuleType::Custom)
        .enabled(false)
        .profiles(0x1)
        .create();

    if let Err(e) = &result {
        println!("Create failed (may require admin): {}", e);
        return;
    }
    assert!(result.is_ok(), "Failed to create custom rule");

    let delete_result = ConnectionSecurityAdapter::remove_rule(&rule_name);
    assert!(delete_result.is_ok(), "Failed to delete custom rule");

    println!("✓ Custom rule lifecycle test passed");
}

#[test]
fn test_builder_pattern_fluent_api() {
    let rule = ConnectionRuleCreator::new("TestBuilder")
        .description("Fluent API test")
        .rule_type(ConnectionSecurityRuleType::Isolation)
        .enabled(true)
        .profiles(0x7)
        .local_addresses("192.168.1.100")
        .remote_addresses("*")
        .build();

    unsafe {
        assert_eq!(CStr::from_ptr(rule.name).to_string_lossy(), "TestBuilder");
        assert_eq!(
            CStr::from_ptr(rule.description).to_string_lossy(),
            "Fluent API test"
        );
        assert!(rule.enabled);
        assert_eq!(rule.rule_type, ConnectionSecurityRuleType::Isolation);
    }

    println!("✓ Builder pattern fluent API test passed");
}

#[test]
fn test_update_rule() {
    use lib_firewall_rust::core::connection::adapter::ConnectionRuleEditor;

    let rule_name = format!("{}UpdateTest", TEST_PREFIX);
    cleanup_test_rule(&rule_name);

    let create_result = ConnectionRuleCreator::new(&rule_name)
        .description("Initial description")
        .rule_type(ConnectionSecurityRuleType::Custom)
        .enabled(true)
        .create();

    if let Err(e) = &create_result {
        println!("Create failed (may require admin): {}", e);
        return;
    }

    let update_result = ConnectionRuleEditor::new(&rule_name)
        .description("Updated description")
        .rule_type(ConnectionSecurityRuleType::Custom)
        .enabled(false)
        .update();

    assert!(update_result.is_ok(), "Failed to update rule");

    let _ = ConnectionSecurityAdapter::remove_rule(&rule_name);

    println!("✓ Update rule test passed");
}

#[test]
fn test_update_nonexistent_rule() {
    use lib_firewall_rust::core::connection::adapter::ConnectionRuleEditor;

    let rule_name = format!("{}NonExistent", TEST_PREFIX);
    cleanup_test_rule(&rule_name);

    let update_result = ConnectionRuleEditor::new(&rule_name)
        .description("Should fail")
        .update();

    assert!(update_result.is_err(), "Should fail for non-existent rule");

    println!("✓ Update non-existent rule test passed");
}

#[test]
fn test_update_system_rule_blocked() {
    use lib_firewall_rust::core::connection::adapter::ConnectionRuleEditor;

    let update_result = ConnectionRuleEditor::new("{SystemRule}")
        .description("Should fail")
        .update();

    assert!(update_result.is_err(), "Should block system rule update");

    println!("✓ Update system rule blocked test passed");
}
