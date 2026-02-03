use crate::core::connection::rule::ConnectionRule;
use crate::core::rule::enums::ConnectionSecurityRuleType;

pub struct ConnectionRuleProperties {
    pub name: String,
    pub description: String,
    pub rule_type: ConnectionSecurityRuleType,
    pub enabled: bool,
    pub profiles: i32,
    pub local_addresses: String,
    pub remote_addresses: String,
    pub endpoint1_ports: String,
    pub endpoint2_ports: String,
    pub protocol: i32,
    pub auth_type: i32,
}

impl ConnectionRuleProperties {
    pub fn from_rule(rule: &ConnectionRule) -> Self {
        unsafe {
            Self {
                name: std::ffi::CStr::from_ptr(rule.name)
                    .to_string_lossy()
                    .into_owned(),
                description: std::ffi::CStr::from_ptr(rule.description)
                    .to_string_lossy()
                    .into_owned(),
                rule_type: rule.rule_type,
                enabled: rule.enabled,
                profiles: rule.profiles,
                local_addresses: std::ffi::CStr::from_ptr(rule.local_addresses)
                    .to_string_lossy()
                    .into_owned(),
                remote_addresses: std::ffi::CStr::from_ptr(rule.remote_addresses)
                    .to_string_lossy()
                    .into_owned(),
                endpoint1_ports: std::ffi::CStr::from_ptr(rule.endpoint1_ports)
                    .to_string_lossy()
                    .into_owned(),
                endpoint2_ports: std::ffi::CStr::from_ptr(rule.endpoint2_ports)
                    .to_string_lossy()
                    .into_owned(),
                protocol: rule.protocol,
                auth_type: rule.auth_type,
            }
        }
    }
}

pub trait ConnectionRuleFactory {
    fn from_props(props: ConnectionRuleProperties) -> Self;
}

impl ConnectionRuleFactory for ConnectionRule {
    fn from_props(p: ConnectionRuleProperties) -> Self {
        Self::new(
            &p.name,
            &p.description,
            p.rule_type,
            p.enabled,
            p.profiles,
            &p.local_addresses,
            &p.remote_addresses,
            &p.endpoint1_ports,
            &p.endpoint2_ports,
            p.protocol,
            p.auth_type,
        )
    }
}
