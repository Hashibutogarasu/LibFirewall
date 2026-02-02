use lib_firewall_rust::*;
use std::ffi::CStr;
use std::slice;

#[test]
fn test_get_inbound_rules() {
    unsafe {
        let init_result = firewall_init();
        assert!(init_result, "Failed to initialize firewall (COM)");

        let mut count = 0;
        let rules_ptr = firewall_get_inbound_rules(&mut count);

        assert!(
            !rules_ptr.is_null(),
            "Returned null pointer for inbound rules"
        );
        assert!(count >= 0, "Rule count should be non-negative");

        println!("Found {} inbound rules", count);

        if count > 0 {
            let slice = slice::from_raw_parts(rules_ptr, count as usize);
            for i in 0..count.min(5) as usize {
                let rule = &slice[i];
                assert!(!rule.name.is_null(), "Rule name is null");

                let name = CStr::from_ptr(rule.name).to_string_lossy();
                println!("Inbound Rule [{}]: {}", i, name);
                assert!(!name.is_empty(), "Rule name is empty");
            }
        }

        firewall_free_inbound_rules(rules_ptr, count);
    }
}

#[test]
fn test_get_outbound_rules() {
    unsafe {
        let init_result = firewall_init();
        assert!(init_result, "Failed to initialize firewall (COM)");

        let mut count = 0;
        let rules_ptr = firewall_get_outbound_rules(&mut count);

        assert!(
            !rules_ptr.is_null(),
            "Returned null pointer for outbound rules"
        );
        assert!(count >= 0, "Rule count should be non-negative");

        println!("Found {} outbound rules", count);

        if count > 0 {
            let slice = slice::from_raw_parts(rules_ptr, count as usize);
            for i in 0..count.min(5) as usize {
                let rule = &slice[i];
                assert!(!rule.name.is_null(), "Rule name is null");

                let name = CStr::from_ptr(rule.name).to_string_lossy();
                println!("Outbound Rule [{}]: {}", i, name);
                assert!(!name.is_empty(), "Rule name is empty");
            }
        }

        firewall_free_outbound_rules(rules_ptr, count);
    }
}
