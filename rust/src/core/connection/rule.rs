use crate::core::rule::enums::ConnectionSecurityRuleType;
use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
pub struct ConnectionRule {
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub rule_type: ConnectionSecurityRuleType,
    pub enabled: bool,
    pub profiles: i32,
    pub local_addresses: *mut c_char,
    pub remote_addresses: *mut c_char,
    pub endpoint1_ports: *mut c_char,
    pub endpoint2_ports: *mut c_char,
    pub protocol: i32,
    pub auth_type: i32,
}

impl ConnectionRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        description: &str,
        rule_type: ConnectionSecurityRuleType,
        enabled: bool,
        profiles: i32,
        local_addresses: &str,
        remote_addresses: &str,
        endpoint1_ports: &str,
        endpoint2_ports: &str,
        protocol: i32,
        auth_type: i32,
    ) -> Self {
        Self {
            name: CString::new(name).unwrap().into_raw(),
            description: CString::new(description).unwrap().into_raw(),
            rule_type,
            enabled,
            profiles,
            local_addresses: CString::new(local_addresses).unwrap().into_raw(),
            remote_addresses: CString::new(remote_addresses).unwrap().into_raw(),
            endpoint1_ports: CString::new(endpoint1_ports).unwrap().into_raw(),
            endpoint2_ports: CString::new(endpoint2_ports).unwrap().into_raw(),
            protocol,
            auth_type,
        }
    }
}
