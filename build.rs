use std::{
    env,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use anyhow::{anyhow, bail, Context};
use walkdir::WalkDir;

fn main() -> anyhow::Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let root_path = env::var_os("FOBNAIL_PO_ROOT")
        .ok_or_else(|| anyhow::Error::msg("FOBNAIL_PO_ROOT variable must point to file containing PEM certificate to install as PO root"))?;
    let ek_cert_path = env::var_os("FOBNAIL_EK_ROOT_DIR");
    // Additional root to install, used for testing Fobnail with TPM simulator.
    let extra_ek_root = env::var_os("FOBNAIL_EXTRA_EK_ROOT");

    if ek_cert_path.is_none() && extra_ek_root.is_none() {
        bail!("Either FOBNAIL_EK_ROOT_DIR or FOBNAIL_EXTRA_EK_ROOT variable must be set");
    }

    println!("cargo:rerun-if-env-changed=FOBNAIL_PO_ROOT");
    println!("cargo:rerun-if-env-changed=FOBNAIL_EK_ROOT_DIR");
    println!("cargo:rerun-if-env-changed=FOBNAIL_EXTRA_EK_ROOT");

    let root_ca_out = Path::new(&out_dir).join("embedded_certstore.rs");
    let mut out_file = File::create(&root_ca_out)
        .context(anyhow!("Failed to create {}", root_ca_out.display()))?;

    out_file
        .write_all(b"pub static EMBEDDED_CERTIFICATES: &[&[u8]] = &[\n")
        .unwrap();

    // Platform Owner certificate must be loaded first. certmgr assumes this is
    // the first certificate in array.
    load_cert(&mut out_file, &root_path)?;

    // Install extra certificate first for faster lookup.
    if let Some(extra_ek_root) = extra_ek_root {
        let path = Path::new(&extra_ek_root);
        println!("cargo:rerun-if-changed={}", path.display());

        load_cert(&mut out_file, &extra_ek_root)
            .context(anyhow!("Failed to load {}", path.display()))?;
    }

    if let Some(ek_cert_path) = ek_cert_path {
        println!(
            "cargo:rerun-if-changed={}",
            Path::new(&ek_cert_path).display()
        );
        for entry in WalkDir::new(ek_cert_path).max_depth(1) {
            let entry = entry?;
            if entry.file_type().is_file() {
                load_cert(&mut out_file, entry.path())
                    .context(anyhow!("Failed to load {}", entry.path().display()))?;
            }
        }
    }

    out_file.write_all(b"];\n").unwrap();
    out_file.flush()?;

    Ok(())
}

/// Loads PEM certificate, converts it to DER and generates code ready for
/// embedding.
fn load_cert<W: Write, T: AsRef<Path> + ?Sized>(out: &mut W, cert_path: &T) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(cert_path)
        .context("Failed to load Platform Owner root CA")?;
    println!("cargo:rerun-if-changed={}", cert_path.as_ref().display());

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let mut error = anyhow!("Certificate is neither a valid PEM nor DER");
    match decode_pem(&data) {
        Ok(data) => {
            error = anyhow!("Invalid PEM certificate");
            validate_der_cert(&data).context(error)?;
            write_cert(out, &data)?;
            return Ok(());
        }
        Err(e) => {
            error = e.context(error);
        }
    }

    // If not a valid PEM then maybe it's PEM certificate.
    validate_der_cert(&data).context(error)?;
    write_cert(out, &data)?;
    Ok(())
}

/// Check whether `data` is a valid DER-encoded certificate.
fn validate_der_cert(data: &[u8]) -> Result<(), x509_cert::der::Error> {
    let mut decoder = x509_cert::der::Decoder::new(data)?;
    decoder.decode::<x509_cert::Certificate>()?;
    Ok(())
}

/// Decodes PEM-encoded certificates and returns its DER representation.
fn decode_pem(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut decoder = pem_rfc7468::Decoder::new(data)?;
    if decoder.type_label() != "CERTIFICATE" {
        bail!("Expected CERTIFICATE, got {}", decoder.type_label());
    }

    decoder.decode_to_end(&mut decoded)?;
    Ok(decoded)
}

fn write_cert<W: Write>(out: &mut W, der: &[u8]) -> io::Result<()> {
    out.write_all(b"    &[\n")?;

    for chunk in der.chunks(16) {
        struct H<'a>(&'a [u8]);
        impl std::fmt::Display for H<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                for b in self.0 {
                    write!(f, "0x{:02x}, ", *b)?;
                }
                Ok(())
            }
        }

        out.write_all(format!("        {}\n", H(chunk)).as_bytes())?;
    }

    out.write_all(b"    ],\n")?;

    Ok(())
}
