use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
pub struct ConnectionRule {
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub enabled: bool,
}

impl ConnectionRule {
    pub fn new(name: &str, description: &str, enabled: bool) -> Self {
        Self {
            name: CString::new(name).unwrap().into_raw(),
            description: CString::new(description).unwrap().into_raw(),
            enabled,
        }
    }
}
