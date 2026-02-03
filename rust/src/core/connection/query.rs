use crate::core::builder::query::{Query, QueryBuilder};
use crate::core::connection::rule::ConnectionRule;
use crate::core::rule::enums::ConnectionSecurityRuleType;
use windows::core::PCWSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};

pub struct ConnectionSecurityQuery;

impl Query for ConnectionSecurityQuery {
    type Output = Vec<ConnectionRule>;

    fn execute(self) -> Self::Output {
        let mut rules = Vec::new();

        // Connection security rules are stored in registry under:
        // HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\ConSecRules

        let reg_path = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\ConSecRules\0";
        let wide_path: Vec<u16> = reg_path.encode_utf16().collect();

        unsafe {
            let mut hkey = HKEY::default();
            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(wide_path.as_ptr()),
                None,
                KEY_READ,
                &mut hkey,
            );

            if result.is_err() {
                return rules;
            }

            let mut index = 0u32;
            let mut name_buf = [0u16; 256];
            let mut data_buf = [0u8; 4096];

            loop {
                let mut name_len = name_buf.len() as u32;
                let mut data_len = data_buf.len() as u32;
                let mut value_type = 0u32;

                let result = RegEnumValueW(
                    hkey,
                    index,
                    Some(windows::core::PWSTR::from_raw(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    Some(&mut value_type),
                    Some(data_buf.as_mut_ptr()),
                    Some(&mut data_len),
                );

                if result.is_err() {
                    break;
                }

                let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let data = String::from_utf16_lossy(std::slice::from_raw_parts(
                    data_buf.as_ptr() as *const u16,
                    (data_len as usize / 2).saturating_sub(1),
                ));

                if let Some(rule) = Self::parse_rule_string(&name, &data) {
                    rules.push(rule);
                }

                index += 1;
            }

            let _ = RegCloseKey(hkey);
        }

        rules
    }
}

impl ConnectionSecurityQuery {
    fn parse_rule_string(name: &str, data: &str) -> Option<ConnectionRule> {
        // Connection security rules are stored as pipe-delimited strings
        // Format varies but typically includes: Version|Action|Active|Dir|Protocol|...
        let parts: Vec<&str> = data.split('|').collect();

        if parts.len() < 3 {
            return None;
        }

        let enabled = parts.get(2).map(|s| *s == "TRUE").unwrap_or(false);
        let rule_type = ConnectionSecurityRuleType::Custom; // Default to custom

        Some(ConnectionRule::new(
            name, "", // Description not stored in registry format
            rule_type, enabled, 0x7FFFFFFF, // All profiles
            "*",        // All local addresses
            "*",        // All remote addresses
            "",         // Endpoint1 ports
            "",         // Endpoint2 ports
            256,        // Any protocol
            0,          // No auth type specified
        ))
    }
}

pub struct ConnectionSecurityRuleBuilder;

impl QueryBuilder for ConnectionSecurityRuleBuilder {
    type Query = ConnectionSecurityQuery;
    fn build(self) -> Self::Query {
        ConnectionSecurityQuery
    }
}
