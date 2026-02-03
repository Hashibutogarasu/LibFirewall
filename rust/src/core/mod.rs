pub mod builder;
pub mod connection;
#[path = "memory/lib.rs"]
pub mod memory;
pub mod rule;

use crate::core::builder::executor::QueryExecutor;
use crate::core::builder::query::{InboundRuleBuilder, OutboundRuleBuilder};
use crate::core::rule::inbound::InboundRule;
use crate::core::rule::outbound::OutboundRule;
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
