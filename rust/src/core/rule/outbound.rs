use crate::core::rule::enums::{RuleAction, RuleDirection};
use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
pub struct OutboundRule {
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub enabled: bool,
}

impl OutboundRule {
    pub fn new(name: &str, description: &str, action: RuleAction, enabled: bool) -> Self {
        Self {
            name: CString::new(name).unwrap().into_raw(),
            description: CString::new(description).unwrap().into_raw(),
            direction: RuleDirection::Outbound,
            action,
            enabled,
        }
    }
}
