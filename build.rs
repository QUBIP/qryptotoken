// Copyright 2023 Simo Sorce
// See LICENSE.txt file for terms

#[derive(Debug)]
pub struct Pkcs11Callbacks;

impl bindgen::callbacks::ParseCallbacks for Pkcs11Callbacks {
    fn int_macro(
        &self,
        name: &str,
        _: i64,
    ) -> Option<bindgen::callbacks::IntKind> {
        if name == "CK_TRUE" || name == "CK_FALSE" {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "CK_BBOOL",
                is_signed: false,
            })
        } else if name.starts_with("CRYPTOKI_VERSION") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "CK_BYTE",
                is_signed: false,
            })
        } else if name.starts_with("CK") {
            Some(bindgen::callbacks::IntKind::Custom {
                name: "CK_ULONG",
                is_signed: false,
            })
        } else {
            None
        }
    }
}

#[allow(unused)]
fn build_ossl() {
    let openssl_path = std::path::PathBuf::from("openssl")
        .canonicalize()
        .expect("cannot canonicalize path");

    #[cfg(feature = "fips")]
    let (libpath, bldargs) = {
        let providers_path = openssl_path
            .join("providers")
            .canonicalize()
            .expect("OpenSSL providers path unavailable");

        let libfips = format!("{}/libfips.a", providers_path.to_string_lossy());
        let buildargs = [
            "--debug",
            "enable-fips",
            "no-mdc2",
            "no-ec2m",
            "no-sm2",
            "no-sm4",
            "-DREDHAT_FIPS_VERSION=\\\"0.0.1-test\\\"",
        ];

        println!(
            "cargo:rustc-link-search={}",
            providers_path.to_string_lossy()
        );
        println!("cargo:rustc-link-lib=static=fips");
        println!("cargo::rerun-if-changed={}", libfips);

        (libfips, buildargs)
    };

    #[cfg(not(feature = "fips"))]
    let (libpath, bldargs) = {
        let libcrypto =
            format!("{}/libcrypto.a", openssl_path.to_string_lossy());

        println!("cargo:rustc-link-search={}", openssl_path.to_str().unwrap());
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo::rerun-if-changed={}", libcrypto);

        (libcrypto, ["--debug"])
    };

    match std::path::Path::new(&libpath).try_exists() {
        Ok(true) => (),
        _ => {
            /* openssl: ./Configure --debug enable-fips */
            if !std::process::Command::new("./Configure")
                .current_dir(&openssl_path)
                .args(bldargs)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("could not run openssl `Configure`")
                .status
                .success()
            {
                // Panic if the command was not successful.
                panic!("could not configure OpenSSL");
            }

            if !std::process::Command::new("make")
                .current_dir(&openssl_path)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .output()
                .expect("could not run openssl `make`")
                .status
                .success()
            {
                // Panic if the command was not successful.
                panic!("could not build OpenSSL");
            }
        }
    }

    let include_path = openssl_path
        .join("include")
        .canonicalize()
        .expect("OpenSSL include path unavailable");

    bindgen::Builder::default()
        .header("fips.h")
        .clang_arg(format!("-I{}", include_path.to_str().unwrap()))
        .clang_arg("-std=c90") /* workaround [-Wimplicit-int] */
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .allowlist_item("ossl_.*")
        .allowlist_item("OSSL_.*")
        .allowlist_item("openssl_.*")
        .allowlist_item("OPENSSL_.*")
        .allowlist_item("CRYPTO_.*")
        .allowlist_item("c_.*")
        .allowlist_item("EVP_.*")
        .allowlist_item("evp_.*")
        .allowlist_item("BN_.*")
        .allowlist_item("LN_aes.*")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/ossl/bindings.rs")
        .expect("Couldn't write bindings!");
}

fn main() {
    /* PKCS11 Headers */
    let pkcs11_header = "pkcs11_headers/3.1/pkcs11.h";
    println!("cargo::rerun-if-changed={}", pkcs11_header);
    let nss_pkcs11_header = "pkcs11_headers/nss_vendor_extension.h";
    println!("cargo::rerun-if-changed={}", nss_pkcs11_header);
    bindgen::Builder::default()
        .header(pkcs11_header)
        .derive_default(true)
        .formatter(bindgen::Formatter::Prettyplease)
        .blocklist_type("CK_FUNCTION_LIST_PTR")
        .blocklist_type("CK_FUNCTION_LIST_3_0_PTR")
        .blocklist_type("CK_INTERFACE")
        .parse_callbacks(Box::new(Pkcs11Callbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("src/pkcs11/bindings.rs")
        .expect("Couldn't write bindings!");

    /* OpenSSL Cryptography */
    #[cfg(not(feature = "pure-rust"))]
    println!("cargo::rerun-if-changed={}", ".git/modules/openssl/HEAD");
    #[cfg(not(feature = "pure-rust"))]
    build_ossl();
}
