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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionSecurityRuleType {
    Isolation = 1,
    AuthenticationExemption = 2,
    ServerToServer = 3,
    Tunnel = 4,
    Custom = 5,
}

impl ConnectionSecurityRuleType {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(val: i32) -> Self {
        match val {
            1 => ConnectionSecurityRuleType::Isolation,
            2 => ConnectionSecurityRuleType::AuthenticationExemption,
            3 => ConnectionSecurityRuleType::ServerToServer,
            4 => ConnectionSecurityRuleType::Tunnel,
            _ => ConnectionSecurityRuleType::Custom,
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Any = 256,
    Tcp = 6,
    Udp = 17,
    Icmpv4 = 1,
    Icmpv6 = 58,
}

impl IpProtocol {
    pub fn to_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(val: i32) -> Option<Self> {
        match val {
            256 => Some(IpProtocol::Any),
            6 => Some(IpProtocol::Tcp),
            17 => Some(IpProtocol::Udp),
            1 => Some(IpProtocol::Icmpv4),
            58 => Some(IpProtocol::Icmpv6),
            _ => None,
        }
    }
}
