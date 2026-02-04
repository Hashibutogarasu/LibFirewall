use crate::core::rule::enums::{IpProtocol, RuleAction};
use crate::core::rule::inbound::InboundRule;
use crate::core::rule::outbound::OutboundRule;
use std::ffi::CStr;
use windows::core::{Result, BSTR};
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, NetFwPolicy2, NetFwRule, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
    NET_FW_RULE_DIRECTION, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};

const DEFAULT_GROUPING: &str = "@FirewallAPI.dll,-23255";

pub struct FirewallAdapter;

impl FirewallAdapter {
    pub fn add_inbound_rule(rule: &InboundRule) -> Result<()> {
        unsafe { Self::add_rule(rule, NET_FW_RULE_DIR_IN) }
    }

    pub fn add_outbound_rule(rule: &OutboundRule) -> Result<()> {
        unsafe { Self::add_rule(rule, NET_FW_RULE_DIR_OUT) }
    }

    unsafe fn add_rule<T>(rule: &T, direction: NET_FW_RULE_DIRECTION) -> Result<()>
    where
        T: RuleTraits,
    {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;
        let rules = policy.Rules()?;
        let fw_rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_ALL)?;

        fw_rule.SetName(&BSTR::from(rule.name()))?;
        fw_rule.SetDescription(&BSTR::from(rule.description()))?;
        fw_rule.SetApplicationName(&BSTR::from(rule.application_name()))?;
        fw_rule.SetServiceName(&BSTR::from(rule.service_name()))?;
        fw_rule.SetProtocol(rule.protocol())?;
        fw_rule.SetLocalPorts(&BSTR::from(rule.local_ports()))?;
        fw_rule.SetRemotePorts(&BSTR::from(rule.remote_ports()))?;
        fw_rule.SetLocalAddresses(&BSTR::from(rule.local_addresses()))?;
        fw_rule.SetRemoteAddresses(&BSTR::from(rule.remote_addresses()))?;
        fw_rule.SetDirection(direction)?;
        fw_rule.SetEnabled(VARIANT_BOOL::from(rule.enabled()))?;
        fw_rule.SetGrouping(&BSTR::from(rule.grouping()))?;
        fw_rule.SetProfiles(rule.profiles())?;
        fw_rule.SetAction(if rule.action() == RuleAction::Allow {
            NET_FW_ACTION_ALLOW
        } else {
            NET_FW_ACTION_BLOCK
        })?;
        fw_rule.SetInterfaceTypes(&BSTR::from(rule.interface_types()))?;
        fw_rule.SetEdgeTraversal(VARIANT_BOOL::from(rule.edge_traversal()))?;

        rules.Add(&fw_rule)?;
        Ok(())
    }

    pub fn delete_rule(name: &str) -> Result<()> {
        unsafe {
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;
            let rules = policy.Rules()?;
            rules.Remove(&BSTR::from(name))
        }
    }

    pub fn update_inbound_rule(rule: &InboundRule) -> Result<()> {
        unsafe { Self::update_rule_internal(rule) }
    }

    pub fn update_outbound_rule(rule: &OutboundRule) -> Result<()> {
        unsafe { Self::update_rule_internal(rule) }
    }

    unsafe fn update_rule_internal<T>(rule: &T) -> Result<()>
    where
        T: RuleTraits,
    {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;
        let rules = policy.Rules()?;
        let fw_rule = rules.Item(&BSTR::from(rule.name()))?;

        fw_rule.SetDescription(&BSTR::from(rule.description()))?;
        fw_rule.SetApplicationName(&BSTR::from(rule.application_name()))?;
        fw_rule.SetServiceName(&BSTR::from(rule.service_name()))?;
        fw_rule.SetProtocol(rule.protocol())?;
        fw_rule.SetLocalPorts(&BSTR::from(rule.local_ports()))?;
        fw_rule.SetRemotePorts(&BSTR::from(rule.remote_ports()))?;
        fw_rule.SetLocalAddresses(&BSTR::from(rule.local_addresses()))?;
        fw_rule.SetRemoteAddresses(&BSTR::from(rule.remote_addresses()))?;
        fw_rule.SetEnabled(VARIANT_BOOL::from(rule.enabled()))?;
        fw_rule.SetGrouping(&BSTR::from(rule.grouping()))?;
        fw_rule.SetProfiles(rule.profiles())?;
        fw_rule.SetAction(if rule.action() == RuleAction::Allow {
            NET_FW_ACTION_ALLOW
        } else {
            NET_FW_ACTION_BLOCK
        })?;
        fw_rule.SetInterfaceTypes(&BSTR::from(rule.interface_types()))?;
        fw_rule.SetEdgeTraversal(VARIANT_BOOL::from(rule.edge_traversal()))?;

        Ok(())
    }
}

trait RuleTraits {
    fn name(&self) -> String;
    fn description(&self) -> String;
    fn application_name(&self) -> String;
    fn service_name(&self) -> String;
    fn grouping(&self) -> String;
    fn protocol(&self) -> i32;
    fn local_ports(&self) -> String;
    fn remote_ports(&self) -> String;
    fn local_addresses(&self) -> String;
    fn remote_addresses(&self) -> String;
    fn enabled(&self) -> bool;
    fn profiles(&self) -> i32;
    fn action(&self) -> RuleAction;
    fn interface_types(&self) -> String;
    fn edge_traversal(&self) -> bool;
}

macro_rules! impl_rule_traits {
    ($t:ty) => {
        impl RuleTraits for $t {
            fn name(&self) -> String {
                unsafe { CStr::from_ptr(self.name).to_string_lossy().to_string() }
            }
            fn description(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.description)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn application_name(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.application_name)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn service_name(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.service_name)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn grouping(&self) -> String {
                unsafe { CStr::from_ptr(self.grouping).to_string_lossy().to_string() }
            }
            fn protocol(&self) -> i32 {
                self.protocol
            }
            fn local_ports(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.local_ports)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn remote_ports(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.remote_ports)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn local_addresses(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.local_addresses)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn remote_addresses(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.remote_addresses)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn enabled(&self) -> bool {
                self.enabled
            }
            fn profiles(&self) -> i32 {
                self.profiles
            }
            fn action(&self) -> RuleAction {
                self.action
            }
            fn interface_types(&self) -> String {
                unsafe {
                    CStr::from_ptr(self.interface_types)
                        .to_string_lossy()
                        .to_string()
                }
            }
            fn edge_traversal(&self) -> bool {
                self.edge_traversal
            }
        }
    };
}

impl_rule_traits!(InboundRule);
impl_rule_traits!(OutboundRule);

pub struct InboundRuleCreator {
    name: String,
    description: String,
    action: RuleAction,
    enabled: bool,
    protocol: i32,
    local_ports: String,
    remote_ports: String,
    local_addresses: String,
    remote_addresses: String,
    profiles: i32,
    interface_types: String,
    edge_traversal: bool,
    application_name: String,
    service_name: String,
    grouping: String,
    local_user_owner: String,
}

impl InboundRuleCreator {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            action: RuleAction::Block,
            enabled: true,
            protocol: IpProtocol::Any.to_i32(),
            local_ports: String::new(),
            remote_ports: String::new(),
            local_addresses: String::new(),
            remote_addresses: String::new(),
            profiles: 2147483647, // All
            interface_types: "All".to_string(),
            edge_traversal: false,
            application_name: String::new(),
            service_name: String::new(),
            grouping: DEFAULT_GROUPING.to_string(),
            local_user_owner: String::new(),
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn action(mut self, action: RuleAction) -> Self {
        self.action = action;
        self
    }

    pub fn protocol(mut self, proto: IpProtocol) -> Self {
        self.protocol = proto.to_i32();
        self
    }

    pub fn local_ports(mut self, ports: &str) -> Self {
        self.local_ports = ports.to_string();
        self
    }

    pub fn application_name(mut self, app: &str) -> Self {
        self.application_name = app.to_string();
        self
    }

    pub fn grouping(mut self, grp: &str) -> Self {
        self.grouping = grp.to_string();
        self
    }

    pub fn local_user_owner(mut self, owner: &str) -> Self {
        self.local_user_owner = owner.to_string();
        self
    }

    pub fn create(&self) -> Result<()> {
        let rule = InboundRule::new(
            &self.name,
            &self.description,
            self.action,
            self.enabled,
            self.protocol,
            &self.local_ports,
            &self.remote_ports,
            &self.local_addresses,
            &self.remote_addresses,
            self.profiles,
            &self.interface_types,
            self.edge_traversal,
            "",
            "",
            "",
            &self.application_name,
            &self.service_name,
            &self.grouping,
            &self.local_user_owner,
        );
        FirewallAdapter::add_inbound_rule(&rule)
    }
}

pub struct OutboundRuleCreator {
    name: String,
    description: String,
    action: RuleAction,
    enabled: bool,
    protocol: i32,
    local_ports: String,
    remote_ports: String,
    local_addresses: String,
    remote_addresses: String,
    profiles: i32,
    interface_types: String,
    edge_traversal: bool,
    application_name: String,
    service_name: String,
    grouping: String,
    local_user_owner: String,
}

impl OutboundRuleCreator {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            action: RuleAction::Block,
            enabled: true,
            protocol: IpProtocol::Any.to_i32(),
            local_ports: String::new(),
            remote_ports: String::new(),
            local_addresses: String::new(),
            remote_addresses: String::new(),
            profiles: 2147483647,
            interface_types: "All".to_string(),
            edge_traversal: false,
            application_name: String::new(),
            service_name: String::new(),
            grouping: DEFAULT_GROUPING.to_string(),
            local_user_owner: String::new(),
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn action(mut self, action: RuleAction) -> Self {
        self.action = action;
        self
    }

    pub fn protocol(mut self, proto: IpProtocol) -> Self {
        self.protocol = proto.to_i32();
        self
    }

    pub fn remote_ports(mut self, ports: &str) -> Self {
        self.remote_ports = ports.to_string();
        self
    }

    pub fn application_name(mut self, app: &str) -> Self {
        self.application_name = app.to_string();
        self
    }

    pub fn grouping(mut self, grp: &str) -> Self {
        self.grouping = grp.to_string();
        self
    }

    pub fn local_user_owner(mut self, owner: &str) -> Self {
        self.local_user_owner = owner.to_string();
        self
    }

    pub fn create(&self) -> Result<()> {
        let rule = OutboundRule::new(
            &self.name,
            &self.description,
            self.action,
            self.enabled,
            self.protocol,
            &self.local_ports,
            &self.remote_ports,
            &self.local_addresses,
            &self.remote_addresses,
            self.profiles,
            &self.interface_types,
            self.edge_traversal,
            "",
            "",
            "",
            &self.application_name,
            &self.service_name,
            &self.grouping,
            &self.local_user_owner,
        );
        FirewallAdapter::add_outbound_rule(&rule)
    }
}

pub struct InboundRuleEditor {
    creator: InboundRuleCreator,
}

impl InboundRuleEditor {
    pub fn new(name: &str) -> Self {
        Self {
            creator: InboundRuleCreator::new(name),
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.creator.description = desc.to_string();
        self
    }

    pub fn grouping(mut self, grp: &str) -> Self {
        self.creator.grouping = grp.to_string();
        self
    }

    pub fn local_user_owner(mut self, owner: &str) -> Self {
        self.creator.local_user_owner = owner.to_string();
        self
    }

    pub fn update(&self) -> Result<()> {
        let rule = InboundRule::new(
            &self.creator.name,
            &self.creator.description,
            self.creator.action,
            self.creator.enabled,
            self.creator.protocol,
            &self.creator.local_ports,
            &self.creator.remote_ports,
            &self.creator.local_addresses,
            &self.creator.remote_addresses,
            self.creator.profiles,
            &self.creator.interface_types,
            self.creator.edge_traversal,
            "",
            "",
            "",
            &self.creator.application_name,
            &self.creator.service_name,
            &self.creator.grouping,
            &self.creator.local_user_owner,
        );
        FirewallAdapter::update_inbound_rule(&rule)
    }
}

pub struct OutboundRuleEditor {
    creator: OutboundRuleCreator,
}

impl OutboundRuleEditor {
    pub fn new(name: &str) -> Self {
        Self {
            creator: OutboundRuleCreator::new(name),
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.creator.description = desc.to_string();
        self
    }

    pub fn grouping(mut self, grp: &str) -> Self {
        self.creator.grouping = grp.to_string();
        self
    }

    pub fn local_user_owner(mut self, owner: &str) -> Self {
        self.creator.local_user_owner = owner.to_string();
        self
    }

    pub fn update(&self) -> Result<()> {
        let rule = OutboundRule::new(
            &self.creator.name,
            &self.creator.description,
            self.creator.action,
            self.creator.enabled,
            self.creator.protocol,
            &self.creator.local_ports,
            &self.creator.remote_ports,
            &self.creator.local_addresses,
            &self.creator.remote_addresses,
            self.creator.profiles,
            &self.creator.interface_types,
            self.creator.edge_traversal,
            "",
            "",
            "",
            &self.creator.application_name,
            &self.creator.service_name,
            &self.creator.grouping,
            &self.creator.local_user_owner,
        );
        FirewallAdapter::update_outbound_rule(&rule)
    }
}
