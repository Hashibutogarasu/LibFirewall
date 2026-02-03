pub mod builder;
pub mod connection;
#[path = "memory/lib.rs"]
pub mod memory;
pub mod rule;

use crate::core::builder::executor::QueryExecutor;
use crate::core::builder::query::{InboundRuleBuilder, OutboundRuleBuilder};
use crate::core::connection::adapter::ConnectionSecurityAdapter;
use crate::core::connection::rule::ConnectionRule;
use crate::core::rule::adapter::FirewallAdapter;
use crate::core::rule::inbound::InboundRule;
use crate::core::rule::outbound::OutboundRule;
use std::ffi::CStr;
use std::os::raw::c_char;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

#[no_mangle]
pub extern "C" fn firewall_init() -> bool {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        hr.is_ok()
    }
}

#[no_mangle]
pub extern "C" fn firewall_get_inbound_rules(count: *mut i32) -> *mut InboundRule {
    let builder = InboundRuleBuilder;
    let result = QueryExecutor::execute(builder);
    let rules = result.result.0;

    let mut boxed_slice = rules.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len() as i32;
    std::mem::forget(boxed_slice);

    unsafe { *count = len };
    ptr
}

#[no_mangle]
pub extern "C" fn firewall_get_outbound_rules(count: *mut i32) -> *mut OutboundRule {
    let builder = OutboundRuleBuilder;
    let result = QueryExecutor::execute(builder);
    let rules = result.result.1;

    let mut boxed_slice = rules.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len() as i32;
    std::mem::forget(boxed_slice);

    unsafe { *count = len };
    ptr
}

#[no_mangle]
pub extern "C" fn firewall_get_connection_rules(
    count: *mut i32,
) -> *mut crate::core::connection::rule::ConnectionRule {
    use crate::core::connection::query::ConnectionSecurityRuleBuilder;

    let builder = ConnectionSecurityRuleBuilder;
    let result = QueryExecutor::execute(builder);
    let rules = result.result;

    let mut boxed_slice = rules.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len() as i32;
    std::mem::forget(boxed_slice);

    unsafe { *count = len };
    ptr
}

#[no_mangle]
pub extern "C" fn firewall_add_inbound_rule(rule: *const InboundRule) -> bool {
    if rule.is_null() {
        return false;
    }
    unsafe {
        match FirewallAdapter::add_inbound_rule(&*rule) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_add_outbound_rule(rule: *const OutboundRule) -> bool {
    if rule.is_null() {
        return false;
    }
    unsafe {
        match FirewallAdapter::add_outbound_rule(&*rule) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_update_inbound_rule(rule: *const InboundRule) -> bool {
    if rule.is_null() {
        return false;
    }
    unsafe {
        match FirewallAdapter::update_inbound_rule(&*rule) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_update_outbound_rule(rule: *const OutboundRule) -> bool {
    if rule.is_null() {
        return false;
    }
    unsafe {
        match FirewallAdapter::update_outbound_rule(&*rule) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_delete_rule(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    unsafe {
        let name_str = match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        match FirewallAdapter::delete_rule(name_str) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_add_connection_rule(rule: *const ConnectionRule) -> bool {
    if rule.is_null() {
        return false;
    }
    unsafe {
        match ConnectionSecurityAdapter::add_rule(&*rule) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_update_connection_rule(rule: *const ConnectionRule) -> bool {
    if rule.is_null() {
        return false;
    }
    unsafe {
        match ConnectionSecurityAdapter::update_rule(&*rule) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_delete_connection_rule(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    unsafe {
        let name_str = match CStr::from_ptr(name).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        };
        match ConnectionSecurityAdapter::remove_rule(name_str) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}