use std::{
    env,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

fn main() -> Result<(), String> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let root_path = env::var_os("FOBNAIL_PO_ROOT").ok_or_else(|| "FOBNAIL_PO_ROOT variable must point to file containing PEM certificate to install as PO root".to_owned())?;

    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(&root_path)
        .map_err(|e| format!("Failed to load Platform Owner root CA: {}", e))?;
    println!("cargo:rerun-if-changed={}", root_path.to_string_lossy());
    println!("cargo:rerun-if-env-changed=FOBNAIL_PO_ROOT");

    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    let mut decoded = Vec::new();
    let mut decoder = pem_rfc7468::Decoder::new(&data).unwrap();
    if decoder.type_label() != "CERTIFICATE" {
        return Err(format!(
            "Expected CERTIFICATE, got {}",
            decoder.type_label()
        ));
    }

    let der = decoder.decode_to_end(&mut decoded).unwrap();

    let root_ca_out = Path::new(&out_dir).join("root_ca.rs");
    let mut out_file = File::create(root_ca_out).unwrap();

    out_file
        .write_all(b"static PO_CHAIN_ROOT: &[u8] = &[\n")
        .unwrap();
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
        out_file
            .write_all(format!("{}\n", H(chunk)).as_bytes())
            .unwrap();
    }
    out_file.write_all(b"];\n").unwrap();
    out_file.flush().unwrap();

    Ok(())
}
