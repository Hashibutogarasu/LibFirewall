use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDirection {
    Inbound = 1,
    Outbound = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Block = 0,
    Allow = 1,
}

pub trait FirewallRule {
    fn new(name: &str, description: &str, action: RuleAction, enabled: bool) -> Self;
}

#[repr(C)]
pub struct InboundRule {
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub enabled: bool,
}

impl FirewallRule for InboundRule {
    fn new(name: &str, description: &str, action: RuleAction, enabled: bool) -> Self {
        Self {
            name: CString::new(name).unwrap().into_raw(),
            description: CString::new(description).unwrap().into_raw(),
            direction: RuleDirection::Inbound,
            action,
            enabled,
        }
    }
}

#[repr(C)]
pub struct OutboundRule {
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub enabled: bool,
}

impl FirewallRule for OutboundRule {
    fn new(name: &str, description: &str, action: RuleAction, enabled: bool) -> Self {
        Self {
            name: CString::new(name).unwrap().into_raw(),
            description: CString::new(description).unwrap().into_raw(),
            direction: RuleDirection::Outbound,
            action,
            enabled,
        }
    }
}
