use crate::core::builder::factory::{RuleFactory, RuleProperties};
use crate::core::rule::inbound::InboundRule;
use crate::core::rule::outbound::OutboundRule;
use windows::core::{Interface, Result};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
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
                    if self.direction == NET_FW_RULE_DIR_IN.0 {
                        inbound_rules = Self::collect_rules::<InboundRule>(&rules);
                    } else if self.direction == NET_FW_RULE_DIR_OUT.0 {
                        outbound_rules = Self::collect_rules::<OutboundRule>(&rules);
                    }
                }
            }
        }

        (inbound_rules, outbound_rules)
    }
}

impl RuleListQuery {
    unsafe fn collect_rules<T: RuleFactory>(rules: &INetFwRules) -> Vec<T> {
        let mut collected = Vec::new();
        let unknown = match rules._NewEnum() {
            Ok(u) => u,
            Err(_) => return collected,
        };
        let enumerator: IEnumVARIANT = match unknown.cast() {
            Ok(e) => e,
            Err(_) => return collected,
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
                    if (dir.0 as i32) == T::direction() {
                        let props = RuleProperties::from_rule(&rule);
                        collected.push(T::from_props(props));
                    }
                }
            }
            let _ = std::mem::replace(&mut variant[0], VARIANT::default());
        }
        collected
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
