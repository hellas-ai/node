#[cfg(feature = "apple-app-attest")]
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/apple_app_attest.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .compile("hellas_apple_app_attest");
        println!("cargo:rustc-link-lib=framework=AppKit");
        println!("cargo:rustc-link-lib=framework=DeviceCheck");
        println!("cargo:rustc-link-lib=framework=Foundation");
    }
}

#[cfg(not(feature = "apple-app-attest"))]
fn main() {}
