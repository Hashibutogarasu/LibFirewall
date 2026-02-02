use crate::models::rule::{FirewallRule, InboundRule, OutboundRule, RuleAction};
use std::ffi::CString;
use std::os::raw::c_char;
use windows::core::{Interface, Result};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NetFwPolicy2, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
    NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_MULTITHREADED,
};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VT_DISPATCH};

#[no_mangle]
pub extern "C" fn firewall_init() -> bool {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        hr.is_ok()
    }
}

unsafe fn get_rules() -> Result<INetFwRules> {
    let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_ALL)?;
    policy.Rules()
}

unsafe fn collect_rules<T, F>(direction_filter: i32, factory: F) -> (*mut T, i32)
where
    F: Fn(&str, &str, RuleAction, bool) -> T,
{
    let rules_result = get_rules();
    if let Err(_) = rules_result {
        return (std::ptr::null_mut(), 0);
    }
    let rules = rules_result.unwrap();

    let mut collected: Vec<T> = Vec::new();

    let unknown = match rules._NewEnum() {
        Ok(u) => u,
        Err(_) => return (std::ptr::null_mut(), 0),
    };
    let enumerator: IEnumVARIANT = match unknown.cast() {
        Ok(e) => e,
        Err(_) => return (std::ptr::null_mut(), 0),
    };

    let mut variant = [VARIANT::default(); 1];
    let mut fetched = 0;

    while unsafe { enumerator.Next(&mut variant, &mut fetched).is_ok() } && fetched == 1 {
        let var = &variant[0];
        let rule_opt: Option<INetFwRule> = unsafe {
            if var.vt() == VT_DISPATCH {
                var.Anonymous
                    .Anonymous
                    .Anonymous
                    .pdispVal
                    .as_ref()
                    .and_then(|d| d.cast().ok())
            } else {
                None
            }
        };

        if let Some(rule) = rule_opt {
            if let Ok(dir) = unsafe { rule.Direction() } {
                if (dir.0 as i32) == direction_filter {
                    let name = unsafe { rule.Name() }.unwrap_or_default().to_string();
                    let description = unsafe { rule.Description() }
                        .unwrap_or_default()
                        .to_string();
                    let enabled_bool = unsafe { rule.Enabled() }.unwrap_or_default().as_bool();
                    let action_val = unsafe { rule.Action() }.unwrap_or(NET_FW_ACTION_BLOCK);

                    let action = if action_val == NET_FW_ACTION_ALLOW {
                        RuleAction::Allow
                    } else {
                        RuleAction::Block
                    };

                    collected.push(factory(&name, &description, action, enabled_bool));
                }
            }
        }

        let _ = std::mem::replace(&mut variant[0], VARIANT::default());
    }

    let mut boxed_slice = collected.into_boxed_slice();
    let ptr = boxed_slice.as_mut_ptr();
    let len = boxed_slice.len() as i32;
    std::mem::forget(boxed_slice);
    (ptr, len)
}

#[no_mangle]
pub extern "C" fn firewall_get_inbound_rules(count: *mut i32) -> *mut InboundRule {
    let (ptr, len) = unsafe {
        collect_rules(NET_FW_RULE_DIR_IN.0, |n, d, a, e| {
            InboundRule::new(n, d, a, e)
        })
    };
    unsafe { *count = len };
    ptr
}

#[no_mangle]
pub extern "C" fn firewall_get_outbound_rules(count: *mut i32) -> *mut OutboundRule {
    let (ptr, len) = unsafe {
        collect_rules(NET_FW_RULE_DIR_OUT.0, |n, d, a, e| {
            OutboundRule::new(n, d, a, e)
        })
    };
    unsafe { *count = len };
    ptr
}

#[no_mangle]
pub extern "C" fn firewall_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn firewall_free_inbound_rules(ptr: *mut InboundRule, len: i32) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len as usize);
        for rule in slice {
            firewall_free_string(rule.name);
            firewall_free_string(rule.description);
        }
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len as usize));
    }
}

#[no_mangle]
pub extern "C" fn firewall_free_outbound_rules(ptr: *mut OutboundRule, len: i32) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len as usize);
        for rule in slice {
            firewall_free_string(rule.name);
            firewall_free_string(rule.description);
        }
        let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len as usize));
    }
}
