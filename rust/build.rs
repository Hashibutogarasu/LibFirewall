fn main() {
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .input_extern_file("src/core/api.rs")
        .input_extern_file("src/models/rule.rs")
        .csharp_dll_name("lib_firewall_rust")
        .csharp_namespace("LibFirewall")
        .csharp_class_accessibility("public")
        .generate_csharp_file("../NativeMethods.cs")
        .unwrap();
}
