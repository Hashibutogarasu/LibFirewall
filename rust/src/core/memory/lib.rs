use crate::core::rule::inbound::InboundRule;
use crate::core::rule::outbound::OutboundRule;
use std::ffi::CString;
use std::os::raw::c_char;

#[no_mangle]
pub extern "C" fn firewall_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_free_inbound_rules(ptr: *mut InboundRule, len: i32) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len as usize);
        for rule in slice {
            firewall_free_string(rule.name);
            firewall_free_string(rule.description);
            firewall_free_string(rule.local_ports);
            firewall_free_string(rule.remote_ports);
            firewall_free_string(rule.local_addresses);
            firewall_free_string(rule.remote_addresses);
            firewall_free_string(rule.interface_types);
            firewall_free_string(rule.local_user_authorized_list);
            firewall_free_string(rule.remote_user_authorized_list);
            firewall_free_string(rule.remote_machine_authorized_list);
            firewall_free_string(rule.application_name);
            firewall_free_string(rule.service_name);
        }
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len as usize));
    }
}

#[no_mangle]
pub extern "C" fn firewall_free_outbound_rules(ptr: *mut OutboundRule, len: i32) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len as usize);
        for rule in slice {
            firewall_free_string(rule.name);
            firewall_free_string(rule.description);
            firewall_free_string(rule.local_ports);
            firewall_free_string(rule.remote_ports);
            firewall_free_string(rule.local_addresses);
            firewall_free_string(rule.remote_addresses);
            firewall_free_string(rule.interface_types);
            firewall_free_string(rule.local_user_authorized_list);
            firewall_free_string(rule.remote_user_authorized_list);
            firewall_free_string(rule.remote_machine_authorized_list);
            firewall_free_string(rule.application_name);
            firewall_free_string(rule.service_name);
        }
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len as usize));
    }
}
