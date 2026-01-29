use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::x509::{X509NameBuilder, X509};
use std::fmt::Write as FmtWrite;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use slipstream_ffi::picoquic::PICOQUIC_RESET_SECRET_SIZE;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug)]
pub(crate) struct ResetSeed {
    pub(crate) bytes: [u8; PICOQUIC_RESET_SECRET_SIZE],
    pub(crate) created: bool,
}

pub(crate) fn load_or_create_reset_seed(path: &Path) -> Result<ResetSeed, String> {
    match load_reset_seed(path) {
        Ok(bytes) => Ok(ResetSeed {
            bytes,
            created: false,
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "Failed to create reset seed directory {}: {}",
                        parent.display(),
                        err
                    )
                })?;
            }
            let mut seed = [0u8; PICOQUIC_RESET_SECRET_SIZE];
            rand_bytes(&mut seed).map_err(|err| err.to_string())?;
            match write_reset_seed(path, &seed) {
                Ok(()) => Ok(ResetSeed {
                    bytes: seed,
                    created: true,
                }),
                Err(write_err) if write_err.kind() == io::ErrorKind::AlreadyExists => {
                    let bytes = load_reset_seed(path)
                        .map_err(|err| format!("Failed reading reset seed: {}", err))?;
                    Ok(ResetSeed {
                        bytes,
                        created: false,
                    })
                }
                Err(write_err) => Err(format!(
                    "Failed to write reset seed {}: {}",
                    path.display(),
                    write_err
                )),
            }
        }
        Err(err) => Err(format!(
            "Failed to read reset seed {}: {}",
            path.display(),
            err
        )),
    }
}

pub(crate) fn ensure_cert_key(cert_path: &Path, key_path: &Path) -> Result<bool, String> {
    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();
    match (cert_exists, key_exists) {
        (true, true) => Ok(false),
        (true, false) => Err(format!(
            "Key file is missing at {} (cert exists at {})",
            key_path.display(),
            cert_path.display()
        )),
        (false, true) => Err(format!(
            "Cert file is missing at {} (key exists at {})",
            cert_path.display(),
            key_path.display()
        )),
        (false, false) => {
            if let Some(parent) = cert_path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "Failed to create cert directory {}: {}",
                        parent.display(),
                        err
                    )
                })?;
            }
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    format!(
                        "Failed to create key directory {}: {}",
                        parent.display(),
                        err
                    )
                })?;
            }
            match generate_self_signed(cert_path, key_path) {
                Ok(()) => Ok(true),
                Err(err) => {
                    if cert_path.exists() && key_path.exists() {
                        Ok(false)
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }
}

fn load_reset_seed(path: &Path) -> io::Result<[u8; PICOQUIC_RESET_SECRET_SIZE]> {
    let contents = fs::read_to_string(path)?;
    parse_hex_seed(&contents).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn parse_hex_seed(input: &str) -> Result<[u8; PICOQUIC_RESET_SECRET_SIZE], String> {
    let trimmed = input.trim();
    if trimmed.len() != PICOQUIC_RESET_SECRET_SIZE * 2 {
        return Err(format!(
            "Reset seed must be {} hex chars (got {})",
            PICOQUIC_RESET_SECRET_SIZE * 2,
            trimmed.len()
        ));
    }
    if !trimmed.is_ascii() {
        return Err("Reset seed must be ASCII hex".to_string());
    }
    let mut seed = [0u8; PICOQUIC_RESET_SECRET_SIZE];
    for (idx, slot) in seed.iter_mut().enumerate() {
        let offset = idx * 2;
        let byte = u8::from_str_radix(&trimmed[offset..offset + 2], 16)
            .map_err(|_| format!("Reset seed contains invalid hex at byte {}", idx))?;
        *slot = byte;
    }
    Ok(seed)
}

fn write_reset_seed(path: &Path, seed: &[u8; PICOQUIC_RESET_SECRET_SIZE]) -> io::Result<()> {
    let mut file = open_new_with_mode(path, 0o600)?;
    let mut buf = String::with_capacity(PICOQUIC_RESET_SECRET_SIZE * 2 + 1);
    for byte in seed {
        let _ = write!(buf, "{:02x}", byte);
    }
    buf.push('\n');
    file.write_all(buf.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

const CERT_VALIDITY_DAYS: i64 = 365_000;
const SECONDS_PER_DAY: i64 = 86_400;
const ASN1_TIME_FORMAT: &[FormatItem<'static>] =
    format_description!("[year][month][day][hour][minute][second]Z");

fn generate_self_signed(cert_path: &Path, key_path: &Path) -> Result<(), String> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|err| format!("Failed to create EC group: {}", err))?;
    let ec_key =
        EcKey::generate(&group).map_err(|err| format!("Failed to generate key: {}", err))?;
    let pkey = PKey::from_ec_key(ec_key).map_err(|err| format!("Failed to create key: {}", err))?;

    let mut name_builder =
        X509NameBuilder::new().map_err(|err| format!("Failed to create subject name: {}", err))?;
    name_builder
        .append_entry_by_text("CN", "slipstream")
        .map_err(|err| format!("Failed to set subject CN: {}", err))?;
    let name = name_builder.build();

    let mut serial_bytes = [0u8; 16];
    rand_bytes(&mut serial_bytes).map_err(|err| err.to_string())?;
    let serial = BigNum::from_slice(&serial_bytes)
        .map_err(|err| format!("Failed to build serial: {}", err))?;
    let serial = serial
        .to_asn1_integer()
        .map_err(|err| format!("Failed to encode serial: {}", err))?;

    let mut builder = X509::builder().map_err(|err| format!("Failed to create cert: {}", err))?;
    builder
        .set_version(2)
        .map_err(|err| format!("Failed to set cert version: {}", err))?;
    builder
        .set_serial_number(&serial)
        .map_err(|err| format!("Failed to set cert serial: {}", err))?;
    builder
        .set_subject_name(&name)
        .map_err(|err| format!("Failed to set subject name: {}", err))?;
    builder
        .set_issuer_name(&name)
        .map_err(|err| format!("Failed to set issuer name: {}", err))?;
    builder
        .set_pubkey(&pkey)
        .map_err(|err| format!("Failed to set public key: {}", err))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System time is before UNIX epoch".to_string())?;
    let now_secs =
        i64::try_from(now.as_secs()).map_err(|_| "System time is out of range".to_string())?;
    let not_before = asn1_time_from_unix_secs(now_secs, "notBefore")?;
    let validity_secs = CERT_VALIDITY_DAYS
        .checked_mul(SECONDS_PER_DAY)
        .ok_or_else(|| "Certificate validity overflowed".to_string())?;
    let not_after_secs = now_secs
        .checked_add(validity_secs)
        .ok_or_else(|| "Certificate validity overflowed".to_string())?;
    let not_after = asn1_time_from_unix_secs(not_after_secs, "notAfter")?;
    builder
        .set_not_before(&not_before)
        .map_err(|err| format!("Failed to set notBefore: {}", err))?;
    builder
        .set_not_after(&not_after)
        .map_err(|err| format!("Failed to set notAfter: {}", err))?;
    builder
        .sign(&pkey, MessageDigest::sha256())
        .map_err(|err| format!("Failed to sign cert: {}", err))?;
    let cert = builder.build();

    let key_pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|err| format!("Failed to encode key: {}", err))?;
    let cert_pem = cert
        .to_pem()
        .map_err(|err| format!("Failed to encode cert: {}", err))?;

    write_pem_file(key_path, &key_pem, 0o600)
        .map_err(|err| format!("Failed to write key {}: {}", key_path.display(), err))?;
    if let Err(err) = write_pem_file(cert_path, &cert_pem, 0o644) {
        let _ = fs::remove_file(key_path);
        return Err(format!(
            "Failed to write cert {}: {}",
            cert_path.display(),
            err
        ));
    }
    Ok(())
}

fn asn1_time_from_unix_secs(seconds: i64, label: &str) -> Result<Asn1Time, String> {
    let dt = OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|err| format!("Failed to convert {} timestamp: {}", label, err))?;
    let time_str = dt
        .format(ASN1_TIME_FORMAT)
        .map_err(|err| format!("Failed to format {}: {}", label, err))?;
    Asn1Time::from_str(&time_str).map_err(|err| {
        format!(
            "Failed to set {} from ASN1 time {}: {}",
            label, time_str, err
        )
    })
}

fn write_pem_file(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = open_new_with_mode(path, mode)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn open_new_with_mode(path: &Path, mode: u32) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!(
            "slipstream-test-{}-{}-{}",
            name,
            std::process::id(),
            suffix
        ));
        path
    }

    #[test]
    fn reset_seed_round_trip() {
        let path = temp_path("reset-seed");
        let seed = load_or_create_reset_seed(&path).expect("create seed");
        assert!(seed.created);
        let reloaded = load_or_create_reset_seed(&path).expect("reload seed");
        assert!(!reloaded.created);
        assert_eq!(seed.bytes, reloaded.bytes);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reset_seed_rejects_bad_length() {
        let path = temp_path("reset-seed-bad");
        fs::write(&path, b"deadbeef").expect("write seed");
        let err = load_or_create_reset_seed(&path).unwrap_err();
        assert!(err.contains("Reset seed must be"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ensure_cert_key_generates_missing() {
        let dir = temp_path("certs");
        fs::create_dir_all(&dir).expect("create temp dir");
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let generated = ensure_cert_key(&cert, &key).expect("generate cert/key");
        assert!(generated);
        assert!(cert.exists(), "cert should exist");
        assert!(key.exists(), "key should exist");
        assert!(fs::metadata(&cert).unwrap().len() > 0);
        assert!(fs::metadata(&key).unwrap().len() > 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let cert_mode = fs::metadata(&cert).unwrap().permissions().mode() & 0o777;
            let key_mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
            assert_eq!(cert_mode, 0o644);
            assert_eq!(key_mode, 0o600);
        }
        let _ = fs::remove_file(&cert);
        let _ = fs::remove_file(&key);
        let _ = fs::remove_dir(&dir);
    }
}
