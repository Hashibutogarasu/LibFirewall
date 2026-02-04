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
    pub protocol: i32,
    pub local_ports: *mut c_char,
    pub remote_ports: *mut c_char,
    pub local_addresses: *mut c_char,
    pub remote_addresses: *mut c_char,
    pub profiles: i32,
    pub interface_types: *mut c_char,
    pub edge_traversal: bool,
    pub local_user_authorized_list: *mut c_char,
    pub remote_user_authorized_list: *mut c_char,
    pub remote_machine_authorized_list: *mut c_char,
    pub application_name: *mut c_char,
    pub service_name: *mut c_char,
    pub grouping: *mut c_char,
    pub local_user_owner: *mut c_char,
}

impl OutboundRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        description: &str,
        action: RuleAction,
        enabled: bool,
        protocol: i32,
        local_ports: &str,
        remote_ports: &str,
        local_addresses: &str,
        remote_addresses: &str,
        profiles: i32,
        interface_types: &str,
        edge_traversal: bool,
        local_user_authorized_list: &str,
        remote_user_authorized_list: &str,
        remote_machine_authorized_list: &str,
        application_name: &str,
        service_name: &str,
        grouping: &str,
        local_user_owner: &str,
    ) -> Self {
        Self {
            name: CString::new(name).unwrap().into_raw(),
            description: CString::new(description).unwrap().into_raw(),
            direction: RuleDirection::Outbound,
            action,
            enabled,
            protocol,
            local_ports: CString::new(local_ports).unwrap().into_raw(),
            remote_ports: CString::new(remote_ports).unwrap().into_raw(),
            local_addresses: CString::new(local_addresses).unwrap().into_raw(),
            remote_addresses: CString::new(remote_addresses).unwrap().into_raw(),
            profiles,
            interface_types: CString::new(interface_types).unwrap().into_raw(),
            edge_traversal,
            local_user_authorized_list: CString::new(local_user_authorized_list)
                .unwrap()
                .into_raw(),
            remote_user_authorized_list: CString::new(remote_user_authorized_list)
                .unwrap()
                .into_raw(),
            remote_machine_authorized_list: CString::new(remote_machine_authorized_list)
                .unwrap()
                .into_raw(),
            application_name: CString::new(application_name).unwrap().into_raw(),
            service_name: CString::new(service_name).unwrap().into_raw(),
            grouping: CString::new(grouping).unwrap().into_raw(),
            local_user_owner: CString::new(local_user_owner).unwrap().into_raw(),
        }
    }
}
