fn main() {
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .csharp_dll_name("lib_firewall_rust")
        .csharp_namespace("LibFirewall")
        .generate_csharp_file("../NativeMethods.cs")
        .unwrap();
}
