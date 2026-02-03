use crate::core::connection::rule::ConnectionRule;
use crate::core::rule::enums::ConnectionSecurityRuleType;
use std::ffi::CStr;
use windows::core::{Result, HRESULT, PCWSTR};
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_SZ,
};

const CONSEC_RULES_PATH: &str =
    "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\ConSecRules\0";

const PROTECTED_PREFIXES: &[&str] = &["IPSEC-", "CoreNet-", "RemoteDesktop-", "@", "{"];

pub struct ConnectionSecurityAdapter;

impl ConnectionSecurityAdapter {
    pub fn rule_exists(name: &str) -> Result<bool> {
        let wide_path: Vec<u16> = CONSEC_RULES_PATH.encode_utf16().collect();
        let wide_name: Vec<u16> = format!("{}\0", name).encode_utf16().collect();

        unsafe {
            let mut hkey = HKEY::default();
            let open_result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(wide_path.as_ptr()),
                None,
                KEY_READ,
                &mut hkey,
            );

            if open_result.is_err() {
                return Ok(false);
            }

            let mut data_size = 0u32;
            let result = RegQueryValueExW(
                hkey,
                PCWSTR::from_raw(wide_name.as_ptr()),
                None,
                None,
                None,
                Some(&mut data_size),
            );

            let _ = RegCloseKey(hkey);

            if result == ERROR_FILE_NOT_FOUND {
                return Ok(false);
            }

            Ok(result.is_ok())
        }
    }

    pub fn is_system_rule(name: &str) -> bool {
        for prefix in PROTECTED_PREFIXES {
            if name.starts_with(prefix) {
                return true;
            }
        }
        false
    }

    pub fn add_rule(rule: &ConnectionRule) -> Result<()> {
        let name = unsafe { CStr::from_ptr(rule.name).to_string_lossy() };

        if Self::rule_exists(&name)? {
            return Err(HRESULT(-1).into());
        }

        Self::add_rule_unchecked(rule)
    }

    pub fn add_rule_unchecked(rule: &ConnectionRule) -> Result<()> {
        let name = unsafe { CStr::from_ptr(rule.name).to_string_lossy() };
        let description = unsafe { CStr::from_ptr(rule.description).to_string_lossy() };
        let local_addresses = unsafe { CStr::from_ptr(rule.local_addresses).to_string_lossy() };
        let remote_addresses = unsafe { CStr::from_ptr(rule.remote_addresses).to_string_lossy() };

        let enabled_str = if rule.enabled { "TRUE" } else { "FALSE" };
        let rule_type_val = rule.rule_type.to_i32();

        let rule_string = format!(
            "v2.30|Action=SecureServer|Active={}|Dir=In|Protocol=Any|LPort=|RPort=|LA4={}|RA4={}|Profile=Domain|Name={}|Desc={}|Mode={}|Auth1=ComputerKerb",
            enabled_str,
            local_addresses,
            remote_addresses,
            name,
            description,
            rule_type_val
        );

        let wide_path: Vec<u16> = CONSEC_RULES_PATH.encode_utf16().collect();
        let wide_name: Vec<u16> = format!("{}\0", name).encode_utf16().collect();
        let wide_value: Vec<u16> = format!("{}\0", rule_string).encode_utf16().collect();

        unsafe {
            let mut hkey = HKEY::default();
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(wide_path.as_ptr()),
                None,
                KEY_WRITE,
                &mut hkey,
            )
            .ok()?;

            let value_bytes =
                std::slice::from_raw_parts(wide_value.as_ptr() as *const u8, wide_value.len() * 2);

            let result = RegSetValueExW(
                hkey,
                PCWSTR::from_raw(wide_name.as_ptr()),
                None,
                REG_SZ,
                Some(value_bytes),
            );

            let _ = RegCloseKey(hkey);
            result.ok()?;
        }

        Ok(())
    }

    pub fn remove_rule(name: &str) -> Result<()> {
        if Self::is_system_rule(name) {
            return Err(HRESULT(-2).into());
        }

        Self::remove_rule_unchecked(name)
    }

    pub fn remove_rule_unchecked(name: &str) -> Result<()> {
        let wide_path: Vec<u16> = CONSEC_RULES_PATH.encode_utf16().collect();
        let wide_name: Vec<u16> = format!("{}\0", name).encode_utf16().collect();

        unsafe {
            let mut hkey = HKEY::default();
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR::from_raw(wide_path.as_ptr()),
                None,
                KEY_WRITE,
                &mut hkey,
            )
            .ok()?;

            let result = RegDeleteValueW(hkey, PCWSTR::from_raw(wide_name.as_ptr()));

            let _ = RegCloseKey(hkey);
            result.ok()?;
        }

        Ok(())
    }

    pub fn update_rule(rule: &ConnectionRule) -> Result<()> {
        let name = unsafe { CStr::from_ptr(rule.name).to_string_lossy() };

        if Self::is_system_rule(&name) {
            return Err(HRESULT(-2).into());
        }

        if !Self::rule_exists(&name)? {
            return Err(HRESULT(-3).into());
        }

        Self::add_rule_unchecked(rule)
    }
}

pub struct ConnectionRuleCreator {
    name: String,
    description: String,
    rule_type: ConnectionSecurityRuleType,
    enabled: bool,
    profiles: i32,
    local_addresses: String,
    remote_addresses: String,
    endpoint1_ports: String,
    endpoint2_ports: String,
    protocol: i32,
    auth_type: i32,
}

impl ConnectionRuleCreator {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            rule_type: ConnectionSecurityRuleType::Custom,
            enabled: true,
            profiles: 0x7FFFFFFF,
            local_addresses: "*".to_string(),
            remote_addresses: "*".to_string(),
            endpoint1_ports: String::new(),
            endpoint2_ports: String::new(),
            protocol: 256,
            auth_type: 0,
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn rule_type(mut self, rt: ConnectionSecurityRuleType) -> Self {
        self.rule_type = rt;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn profiles(mut self, profiles: i32) -> Self {
        self.profiles = profiles;
        self
    }

    pub fn local_addresses(mut self, addr: &str) -> Self {
        self.local_addresses = addr.to_string();
        self
    }

    pub fn remote_addresses(mut self, addr: &str) -> Self {
        self.remote_addresses = addr.to_string();
        self
    }

    pub fn build(&self) -> ConnectionRule {
        ConnectionRule::new(
            &self.name,
            &self.description,
            self.rule_type,
            self.enabled,
            self.profiles,
            &self.local_addresses,
            &self.remote_addresses,
            &self.endpoint1_ports,
            &self.endpoint2_ports,
            self.protocol,
            self.auth_type,
        )
    }

    pub fn create(&self) -> Result<()> {
        let rule = self.build();
        ConnectionSecurityAdapter::add_rule(&rule)
    }
}

pub struct ConnectionRuleEditor {
    name: String,
    description: String,
    rule_type: ConnectionSecurityRuleType,
    enabled: bool,
    profiles: i32,
    local_addresses: String,
    remote_addresses: String,
    endpoint1_ports: String,
    endpoint2_ports: String,
    protocol: i32,
    auth_type: i32,
}

impl ConnectionRuleEditor {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            description: String::new(),
            rule_type: ConnectionSecurityRuleType::Custom,
            enabled: true,
            profiles: 0x7FFFFFFF,
            local_addresses: "*".to_string(),
            remote_addresses: "*".to_string(),
            endpoint1_ports: String::new(),
            endpoint2_ports: String::new(),
            protocol: 256,
            auth_type: 0,
        }
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn rule_type(mut self, rt: ConnectionSecurityRuleType) -> Self {
        self.rule_type = rt;
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn profiles(mut self, profiles: i32) -> Self {
        self.profiles = profiles;
        self
    }

    pub fn local_addresses(mut self, addr: &str) -> Self {
        self.local_addresses = addr.to_string();
        self
    }

    pub fn remote_addresses(mut self, addr: &str) -> Self {
        self.remote_addresses = addr.to_string();
        self
    }

    pub fn build(&self) -> ConnectionRule {
        ConnectionRule::new(
            &self.name,
            &self.description,
            self.rule_type,
            self.enabled,
            self.profiles,
            &self.local_addresses,
            &self.remote_addresses,
            &self.endpoint1_ports,
            &self.endpoint2_ports,
            self.protocol,
            self.auth_type,
        )
    }

    pub fn update(&self) -> Result<()> {
        let rule = self.build();
        ConnectionSecurityAdapter::update_rule(&rule)
    }
}
