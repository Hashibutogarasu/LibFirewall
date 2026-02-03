fn main() {
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .input_extern_file("src/core/mod.rs")
        .input_extern_file("src/core/memory/lib.rs")
        .input_extern_file("src/core/rule/enums.rs")
        .input_extern_file("src/core/rule/inbound.rs")
        .input_extern_file("src/core/rule/outbound.rs")
        .input_extern_file("src/core/connection/rule.rs")
        .csharp_dll_name("lib_firewall_rust")
        .csharp_namespace("LibFirewall")
        .csharp_class_accessibility("public")
        .generate_csharp_file("../NativeMethods.cs")
        .unwrap();
}
