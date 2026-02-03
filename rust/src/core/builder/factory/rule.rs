use crate::core::rule::enums::RuleAction;
use crate::core::rule::inbound::InboundRule;
use crate::core::rule::outbound::OutboundRule;
use windows::core::Interface;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwRule, INetFwRule3, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_OUT,
};

pub struct RuleProperties {
    pub name: String,
    pub description: String,
    pub action: RuleAction,
    pub enabled: bool,
    pub protocol: i32,
    pub local_ports: String,
    pub remote_ports: String,
    pub local_addresses: String,
    pub remote_addresses: String,
    pub profiles: i32,
    pub interface_types: String,
    pub edge_traversal: bool,
    pub local_user_authorized_list: String,
    pub remote_user_authorized_list: String,
    pub remote_machine_authorized_list: String,
    pub application_name: String,
    pub service_name: String,
}

impl RuleProperties {
    pub unsafe fn from_rule(rule: &INetFwRule) -> Self {
        let name = rule.Name().unwrap_or_default().to_string();
        let description = rule.Description().unwrap_or_default().to_string();
        let enabled_bool = rule.Enabled().unwrap_or_default().as_bool();
        let action_val = rule.Action().unwrap_or(NET_FW_ACTION_BLOCK);

        let action = if action_val == NET_FW_ACTION_ALLOW {
            RuleAction::Allow
        } else {
            RuleAction::Block
        };

        let protocol = rule.Protocol().unwrap_or(0);
        let local_ports = rule.LocalPorts().unwrap_or_default().to_string();
        let remote_ports = rule.RemotePorts().unwrap_or_default().to_string();
        let local_addresses = rule.LocalAddresses().unwrap_or_default().to_string();
        let remote_addresses = rule.RemoteAddresses().unwrap_or_default().to_string();
        let profiles = rule.Profiles().unwrap_or(0);
        let interface_types = rule.InterfaceTypes().unwrap_or_default().to_string();
        let edge_traversal = rule.EdgeTraversal().unwrap_or_default().as_bool();

        let (local_usr, remote_usr, remote_machine) = if let Ok(rule3) = rule.cast::<INetFwRule3>()
        {
            (
                rule3
                    .LocalUserAuthorizedList()
                    .unwrap_or_default()
                    .to_string(),
                rule3
                    .RemoteUserAuthorizedList()
                    .unwrap_or_default()
                    .to_string(),
                rule3
                    .RemoteMachineAuthorizedList()
                    .unwrap_or_default()
                    .to_string(),
            )
        } else {
            (String::new(), String::new(), String::new())
        };

        let application_name = rule.ApplicationName().unwrap_or_default().to_string();
        let service_name = rule.ServiceName().unwrap_or_default().to_string();

        RuleProperties {
            name,
            description,
            action,
            enabled: enabled_bool,
            protocol,
            local_ports,
            remote_ports,
            local_addresses,
            remote_addresses,
            profiles,
            interface_types,
            edge_traversal,
            local_user_authorized_list: local_usr,
            remote_user_authorized_list: remote_usr,
            remote_machine_authorized_list: remote_machine,
            application_name,
            service_name,
        }
    }
}

pub trait RuleFactory {
    fn direction() -> i32;
    fn from_props(props: RuleProperties) -> Self;
}

impl RuleFactory for InboundRule {
    fn direction() -> i32 {
        NET_FW_RULE_DIR_IN.0
    }

    fn from_props(p: RuleProperties) -> Self {
        Self::new(
            &p.name,
            &p.description,
            p.action,
            p.enabled,
            p.protocol,
            &p.local_ports,
            &p.remote_ports,
            &p.local_addresses,
            &p.remote_addresses,
            p.profiles,
            &p.interface_types,
            p.edge_traversal,
            &p.local_user_authorized_list,
            &p.remote_user_authorized_list,
            &p.remote_machine_authorized_list,
            &p.application_name,
            &p.service_name,
        )
    }
}

impl RuleFactory for OutboundRule {
    fn direction() -> i32 {
        NET_FW_RULE_DIR_OUT.0
    }

    fn from_props(p: RuleProperties) -> Self {
        Self::new(
            &p.name,
            &p.description,
            p.action,
            p.enabled,
            p.protocol,
            &p.local_ports,
            &p.remote_ports,
            &p.local_addresses,
            &p.remote_addresses,
            p.profiles,
            &p.interface_types,
            p.edge_traversal,
            &p.local_user_authorized_list,
            &p.remote_user_authorized_list,
            &p.remote_machine_authorized_list,
            &p.application_name,
            &p.service_name,
        )
    }
}
