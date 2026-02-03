use crate::core::rule::enums::RuleAction;
use crate::core::rule::inbound::InboundRule;
use crate::core::rule::outbound::OutboundRule;
use windows::core::{Interface, Result};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRule3, INetFwRules, NetFwPolicy2, NET_FW_ACTION_ALLOW,
    NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_ALL};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH};

pub trait Query {
    type Output;
    fn execute(self) -> Self::Output;
}

pub trait QueryBuilder {
    type Query: Query;
    fn build(self) -> Self::Query;
}

pub struct FirewallQueryBuilder;

impl FirewallQueryBuilder {
    pub fn new() -> Self {
        Self
    }
}

pub struct RuleListQuery {
    pub direction: i32,
}

impl Query for RuleListQuery {
    type Output = (Vec<InboundRule>, Vec<OutboundRule>);

    fn execute(self) -> Self::Output {
        let mut inbound_rules = Vec::new();
        let mut outbound_rules = Vec::new();

        unsafe {
            let policy_res: Result<INetFwPolicy2> =
                CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL);
            if let Ok(policy) = policy_res {
                if let Ok(rules) = policy.Rules() {
                    Self::collect_rules_internal(
                        &rules,
                        self.direction,
                        &mut inbound_rules,
                        &mut outbound_rules,
                    );
                }
            }
        }

        (inbound_rules, outbound_rules)
    }
}

impl RuleListQuery {
    unsafe fn collect_rules_internal(
        rules: &INetFwRules,
        direction_filter: i32,
        in_collected: &mut Vec<InboundRule>,
        out_collected: &mut Vec<OutboundRule>,
    ) {
        let unknown = match rules._NewEnum() {
            Ok(u) => u,
            Err(_) => return,
        };
        let enumerator: IEnumVARIANT = match unknown.cast() {
            Ok(e) => e,
            Err(_) => return,
        };

        let mut variant = [VARIANT::default(); 1];
        let mut fetched = 0;

        while enumerator.Next(&mut variant, &mut fetched).is_ok() && fetched == 1 {
            let var = &variant[0];
            let rule_opt: Option<INetFwRule> = if var.vt() == VT_DISPATCH {
                var.Anonymous
                    .Anonymous
                    .Anonymous
                    .pdispVal
                    .as_ref()
                    .and_then(|d| d.cast().ok())
            } else {
                None
            };

            if let Some(rule) = rule_opt {
                if let Ok(dir) = rule.Direction() {
                    if (dir.0 as i32) == direction_filter {
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
                        let remote_addresses =
                            rule.RemoteAddresses().unwrap_or_default().to_string();
                        let profiles = rule.Profiles().unwrap_or(0);
                        let interface_types = rule.InterfaceTypes().unwrap_or_default().to_string();
                        let edge_traversal = rule.EdgeTraversal().unwrap_or_default().as_bool();
                        let (
                            local_user_authorized_list,
                            remote_user_authorized_list,
                            remote_machine_authorized_list,
                        ) = if let Ok(rule3) = rule.cast::<INetFwRule3>() {
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
                        let application_name =
                            rule.ApplicationName().unwrap_or_default().to_string();
                        let service_name = rule.ServiceName().unwrap_or_default().to_string();

                        if direction_filter == NET_FW_RULE_DIR_IN.0 {
                            in_collected.push(InboundRule::new(
                                &name,
                                &description,
                                action,
                                enabled_bool,
                                protocol,
                                &local_ports,
                                &remote_ports,
                                &local_addresses,
                                &remote_addresses,
                                profiles,
                                &interface_types,
                                edge_traversal,
                                &local_user_authorized_list,
                                &remote_user_authorized_list,
                                &remote_machine_authorized_list,
                                &application_name,
                                &service_name,
                            ));
                        } else if direction_filter == NET_FW_RULE_DIR_OUT.0 {
                            out_collected.push(OutboundRule::new(
                                &name,
                                &description,
                                action,
                                enabled_bool,
                                protocol,
                                &local_ports,
                                &remote_ports,
                                &local_addresses,
                                &remote_addresses,
                                profiles,
                                &interface_types,
                                edge_traversal,
                                &local_user_authorized_list,
                                &remote_user_authorized_list,
                                &remote_machine_authorized_list,
                                &application_name,
                                &service_name,
                            ));
                        }
                    }
                }
            }
            let _ = std::mem::replace(&mut variant[0], VARIANT::default());
        }
    }
}

pub struct InboundRuleBuilder;
impl QueryBuilder for InboundRuleBuilder {
    type Query = RuleListQuery;
    fn build(self) -> Self::Query {
        RuleListQuery {
            direction: NET_FW_RULE_DIR_IN.0,
        }
    }
}

pub struct OutboundRuleBuilder;
impl QueryBuilder for OutboundRuleBuilder {
    type Query = RuleListQuery;
    fn build(self) -> Self::Query {
        RuleListQuery {
            direction: NET_FW_RULE_DIR_OUT.0,
        }
    }
}
