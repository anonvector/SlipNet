use libc::{c_char, c_int, c_void, size_t};
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use openssl::x509::X509;
use slipstream_ffi::picoquic::{
    picoquic_quic_t, picoquic_set_verify_certificate_callback, ptls_iovec_t, ptls_t,
    ptls_verify_certificate_t, ptls_verify_sign_cb_fn,
};
use std::fs;

const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
const SIG_ECDSA_SECP521R1_SHA512: u16 = 0x0603;
const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
const SIG_ED25519: u16 = 0x0807;
const SIG_ED448: u16 = 0x0808;
const SIG_RSA_PSS_PSS_SHA256: u16 = 0x0809;
const SIG_RSA_PSS_PSS_SHA384: u16 = 0x080A;
const SIG_RSA_PSS_PSS_SHA512: u16 = 0x080B;
const SIG_ALGO_SENTINEL: u16 = 0xFFFF;

static PINNING_ALGOS: [u16; 15] = [
    SIG_ED25519,
    SIG_ED448,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ECDSA_SECP521R1_SHA512,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PSS_PSS_SHA256,
    SIG_RSA_PSS_PSS_SHA384,
    SIG_RSA_PSS_PSS_SHA512,
    SIG_RSA_PKCS1_SHA256,
    SIG_RSA_PKCS1_SHA384,
    SIG_RSA_PKCS1_SHA512,
    SIG_ALGO_SENTINEL,
];

#[repr(C)]
struct PinnedCertVerifier {
    super_ctx: ptls_verify_certificate_t,
    pinned_der: Vec<u8>,
    pkey: PKey<Public>,
}

pub fn configure_pinned_certificate(
    quic: *mut picoquic_quic_t,
    cert_path: &str,
) -> Result<(), String> {
    if quic.is_null() {
        return Err("QUIC context is null".to_string());
    }
    let (pinned_der, pkey) = load_pinned_cert(cert_path)?;
    let verifier = Box::new(PinnedCertVerifier {
        super_ctx: ptls_verify_certificate_t {
            cb: Some(pinned_verify_certificate),
            algos: PINNING_ALGOS.as_ptr(),
        },
        pinned_der,
        pkey,
    });
    let raw = Box::into_raw(verifier);
    // SAFETY: `quic` is a valid context, and the verifier pointer remains alive until picoquic
    // calls the provided free callback.
    unsafe {
        picoquic_set_verify_certificate_callback(
            quic,
            &mut (*raw).super_ctx,
            Some(pinned_verify_free),
        );
    }
    Ok(())
}

fn load_pinned_cert(cert_path: &str) -> Result<(Vec<u8>, PKey<Public>), String> {
    let pem =
        fs::read(cert_path).map_err(|err| format!("Failed to read cert {}: {}", cert_path, err))?;
    let mut certs = X509::stack_from_pem(&pem)
        .map_err(|err| format!("Failed to parse cert {}: {}", cert_path, err))?;
    if certs.len() != 1 {
        return Err("Pinned cert must contain exactly one certificate".to_string());
    }
    let cert = certs.remove(0);
    let der = cert
        .to_der()
        .map_err(|err| format!("Failed to convert cert to DER: {}", err))?;
    let pkey = cert
        .public_key()
        .map_err(|err| format!("Failed to extract public key: {}", err))?;
    Ok((der, pkey))
}

unsafe extern "C" fn pinned_verify_free(ctx: *mut ptls_verify_certificate_t) {
    if ctx.is_null() {
        return;
    }
    let _ = Box::from_raw(ctx as *mut PinnedCertVerifier);
}

unsafe extern "C" fn pinned_verify_certificate(
    self_ptr: *mut ptls_verify_certificate_t,
    _tls: *mut ptls_t,
    _server_name: *const c_char,
    verify_sign: *mut ptls_verify_sign_cb_fn,
    verify_sign_ctx: *mut *mut c_void,
    certs: *mut ptls_iovec_t,
    num_certs: size_t,
) -> c_int {
    if self_ptr.is_null() || certs.is_null() || num_certs == 0 {
        return -1;
    }
    let verifier = &*(self_ptr as *const PinnedCertVerifier);
    // SAFETY: picotls supplies a valid certificate chain for the duration of the callback.
    let certs = std::slice::from_raw_parts(certs, num_certs);
    let leaf = &certs[0];
    if leaf.base.is_null() || leaf.len == 0 {
        return -1;
    }
    let leaf_bytes = std::slice::from_raw_parts(leaf.base as *const u8, leaf.len);
    if leaf_bytes != verifier.pinned_der.as_slice() {
        return -1;
    }
    if !verify_sign.is_null() {
        *verify_sign = Some(pinned_verify_sign);
    }
    if !verify_sign_ctx.is_null() {
        *verify_sign_ctx = self_ptr as *mut c_void;
    }
    0
}

unsafe extern "C" fn pinned_verify_sign(
    verify_ctx: *mut c_void,
    algo: u16,
    data: ptls_iovec_t,
    sign: ptls_iovec_t,
) -> c_int {
    if verify_ctx.is_null() {
        return -1;
    }
    if data.base.is_null() && data.len == 0 && sign.base.is_null() && sign.len == 0 {
        return 0;
    }
    if data.base.is_null() || sign.base.is_null() {
        return -1;
    }
    let verifier = &*(verify_ctx as *const PinnedCertVerifier);
    // SAFETY: picotls supplies valid message and signature buffers while verifying.
    let data = std::slice::from_raw_parts(data.base as *const u8, data.len);
    let signature = std::slice::from_raw_parts(sign.base as *const u8, sign.len);
    match verify_signature(&verifier.pkey, algo, data, signature) {
        Ok(true) => 0,
        Ok(false) => -1,
        Err(_) => -1,
    }
}

fn verify_signature(
    pkey: &PKey<Public>,
    algo: u16,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    match algo {
        SIG_RSA_PKCS1_SHA256 => {
            verify_rsa(pkey, MessageDigest::sha256(), Padding::PKCS1, data, sig)
        }
        SIG_RSA_PKCS1_SHA384 => {
            verify_rsa(pkey, MessageDigest::sha384(), Padding::PKCS1, data, sig)
        }
        SIG_RSA_PKCS1_SHA512 => {
            verify_rsa(pkey, MessageDigest::sha512(), Padding::PKCS1, data, sig)
        }
        SIG_RSA_PSS_RSAE_SHA256 | SIG_RSA_PSS_PSS_SHA256 => {
            verify_rsa_pss(pkey, MessageDigest::sha256(), data, sig)
        }
        SIG_RSA_PSS_RSAE_SHA384 | SIG_RSA_PSS_PSS_SHA384 => {
            verify_rsa_pss(pkey, MessageDigest::sha384(), data, sig)
        }
        SIG_RSA_PSS_RSAE_SHA512 | SIG_RSA_PSS_PSS_SHA512 => {
            verify_rsa_pss(pkey, MessageDigest::sha512(), data, sig)
        }
        SIG_ECDSA_SECP256R1_SHA256 => verify_ec(pkey, MessageDigest::sha256(), data, sig),
        SIG_ECDSA_SECP384R1_SHA384 => verify_ec(pkey, MessageDigest::sha384(), data, sig),
        SIG_ECDSA_SECP521R1_SHA512 => verify_ec(pkey, MessageDigest::sha512(), data, sig),
        SIG_ED25519 => verify_eddsa(pkey, data, sig, Id::ED25519),
        SIG_ED448 => verify_eddsa(pkey, data, sig, Id::ED448),
        _ => Err(format!("Unsupported signature algorithm 0x{algo:04x}")),
    }
}

fn verify_rsa(
    pkey: &PKey<Public>,
    digest: MessageDigest,
    padding: Padding,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    if pkey.id() != Id::RSA {
        return Err("Expected RSA public key".to_string());
    }
    let mut verifier = Verifier::new(digest, pkey).map_err(|err| err.to_string())?;
    verifier
        .set_rsa_padding(padding)
        .map_err(|err| err.to_string())?;
    verifier.update(data).map_err(|err| err.to_string())?;
    verifier.verify(sig).map_err(|err| err.to_string())
}

fn verify_rsa_pss(
    pkey: &PKey<Public>,
    digest: MessageDigest,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    if !matches!(pkey.id(), Id::RSA | Id::RSA_PSS) {
        return Err("Expected RSA or RSA-PSS public key".to_string());
    }
    let mut verifier = Verifier::new(digest, pkey).map_err(|err| err.to_string())?;
    verifier
        .set_rsa_padding(Padding::PKCS1_PSS)
        .map_err(|err| err.to_string())?;
    verifier
        .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
        .map_err(|err| err.to_string())?;
    verifier
        .set_rsa_mgf1_md(digest)
        .map_err(|err| err.to_string())?;
    verifier.update(data).map_err(|err| err.to_string())?;
    verifier.verify(sig).map_err(|err| err.to_string())
}

fn verify_ec(
    pkey: &PKey<Public>,
    digest: MessageDigest,
    data: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    if pkey.id() != Id::EC {
        return Err("Expected EC public key".to_string());
    }
    let mut verifier = Verifier::new(digest, pkey).map_err(|err| err.to_string())?;
    verifier.update(data).map_err(|err| err.to_string())?;
    verifier.verify(sig).map_err(|err| err.to_string())
}

fn verify_eddsa(
    pkey: &PKey<Public>,
    data: &[u8],
    sig: &[u8],
    expected: Id,
) -> Result<bool, String> {
    if pkey.id() != expected {
        return Err("Expected EdDSA public key".to_string());
    }
    let mut verifier = Verifier::new_without_digest(pkey).map_err(|err| err.to_string())?;
    verifier.update(data).map_err(|err| err.to_string())?;
    verifier.verify(sig).map_err(|err| err.to_string())
}
