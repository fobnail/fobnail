use std::{fmt, fs::OpenOptions, io::Read, path::Path};

use anyhow::Context;
use littlefs2::fs::{Attribute, Filesystem};
use sha2::Digest;

use crate::Flash;

const CERT_ROOT_DIR: &'static str = "/fobnail_client/dat/cert";
// These constants must match with definitions in certmgr/store.rs
const ATTRIBUTE_CERTIFICATE_FLAGS: u8 = 0;
const CERTIFICATE_FLAG_TRUSTED: u8 = 1;

fn cert_from_pem(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .context("Failed to open certificate")?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let pem =
        pem::parse(data).context("Failed to parse PEM (is this a PEM-encoded certificate?)")?;

    Ok(pem.contents)
}

fn read_der(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .context("Failed to open certificate")?;

    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

pub fn install(
    fs: &Filesystem<Flash>,
    path: &Path,
    trusted: bool,
    reinstall: bool,
    der: bool,
) -> anyhow::Result<()> {
    let cert_der = if der {
        read_der(path)?
    } else {
        cert_from_pem(path)?
    };
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der)?;

    let organization = cert
        .subject()
        .iter_organization()
        .next()
        .expect("No organization");

    let organization_path = littlefs2::path::PathBuf::from(organization.as_str().unwrap());
    let mut path = littlefs2::path::PathBuf::from(CERT_ROOT_DIR);
    path.push(&organization_path);

    fs.create_dir_all(&path).unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(&cert_der);
    let sha = hasher.finalize();

    struct HexFormatter<'a>(&'a [u8]);
    impl fmt::Display for HexFormatter<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for x in self.0 {
                write!(f, "{:02x}", *x)?;
            }

            Ok(())
        }
    }

    let hash_str = format!("{}", HexFormatter(sha.as_slice()));
    path.push(&littlefs2::path::PathBuf::from(hash_str.as_str()));

    if path.exists(fs) {
        if reinstall {
            fs.remove(&path).unwrap();
        } else {
            anyhow::bail!("Certificate already in store");
        }
    }

    super::write_file(fs, &path, &cert_der).unwrap();
    println!("Wrote {}", path);

    if trusted {
        let mut attr = Attribute::new(ATTRIBUTE_CERTIFICATE_FLAGS);
        attr.set_data(&[CERTIFICATE_FLAG_TRUSTED]);
        fs.set_attribute(&path, &attr).unwrap();
        println!("Marked {} as trusted", path);
    }

    Ok(())
}
