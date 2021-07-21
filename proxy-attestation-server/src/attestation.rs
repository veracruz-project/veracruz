//! Attestation
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(any(feature = "tz", feature = "linux"))]
pub mod psa;
#[cfg(feature = "sgx")]
pub mod sgx;
#[cfg(feature = "nitro")]
pub mod nitro;

use crate::error::*;
use lazy_static::lazy_static;
use std::sync::atomic::{AtomicI32, Ordering};
use std::io::Read;

use openssl;

lazy_static! {
    static ref DEVICE_ID: AtomicI32 = AtomicI32::new(1);
    static ref CA_CERT_DER: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
}

/// Reads a PEM certificate from `pem_cert_path`, converts it to DER format,
/// and stores it in CA_CERT_DER for use by the service
pub fn load_ca_certificate(pem_cert_path: &str) -> Result<(), ProxyAttestationServerError> {
    let mut f = std::fs::File::open(pem_cert_path)
        .map_err(|err| ProxyAttestationServerError::IOError(err))?;
    let mut buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut buffer)?;
    let cert = openssl::x509::X509::from_pem(&buffer)?;
    let der = cert.to_der()?;
    let mut ccd_guard = CA_CERT_DER.lock()?;
    match *ccd_guard {
        Some(_) => return Err(ProxyAttestationServerError::BadStateError),
        None => {
            *ccd_guard = Some(der);
        }
    }
    return Ok(());
}

fn get_ca_certificate() -> Result<Vec<u8>, ProxyAttestationServerError> {
    let ccd_guard = CA_CERT_DER.lock()?;
    match &*ccd_guard {
        None => return Err(ProxyAttestationServerError::BadStateError),
        Some(der) => return Ok(der.clone()),
    }
}

pub async fn start(body_string: String) -> ProxyAttestationServerResponder {
    let received_bytes = base64::decode(&body_string)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::start failed to decode body_string as base64:{:?}", err);
            err
        })?;

    let parsed = transport_protocol::parse_proxy_attestation_server_request(&received_bytes)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::start failed to parse_proxy_attestation_server_request:{:?}", err);
            err
        })?;

    if !parsed.has_start_msg() {
        println!("proxy-attestation-server::attestation::start doesn't have start_msg");
        return Err(ProxyAttestationServerError::MissingFieldError("start msg"));
    }
    let (protocol, firmware_version) = transport_protocol::parse_start_msg(&parsed);

    let device_id = DEVICE_ID.fetch_add(1, Ordering::SeqCst); 

    match protocol.as_str() {
        #[cfg(feature = "sgx")]
        "sgx" => sgx::start(&firmware_version, device_id),
        #[cfg(any(feature = "tz", feature = "linux"))]
        "psa" => psa::start(&firmware_version, device_id),
        #[cfg(feature = "nitro")]
        "nitro" => nitro::start(&firmware_version, device_id),
        _ => Err(ProxyAttestationServerError::UnknownAttestationTokenError),
    }
}

/// Convert a Certificate Signing Request (CSR) to an X.509 Certificate and
/// sign it
fn convert_csr_to_certificate(csr_der: &[u8]) -> Result<openssl::x509::X509, ProxyAttestationServerError> {
    let csr = openssl::x509::X509Req::from_der(&csr_der)?;
    // first, verify the signature on the CSR
    let public_key = csr.public_key()?;
    let verify_result = csr.verify(&public_key)?;

    if !verify_result {
        println!("proxy_attestation_server::convert_csr_to_certificate verify of CSR failed");
        return Err(ProxyAttestationServerError::CsrVerifyError);
    }
    let mut cert_builder = openssl::x509::X509Builder::new()?;
    cert_builder.set_version(2)?;
    let now = {
        openssl::asn1::Asn1Time::days_from_now(0)?
    };
    cert_builder.set_not_before(&now)?;

    let expiry = {
        openssl::asn1::Asn1Time::days_from_now(1)?
    };
    cert_builder.set_not_after(&expiry)?;

    let serial_number = {
        let sn_bignum = openssl::bn::BigNum::from_u32(23)?;
        openssl::asn1::Asn1Integer::from_bn(&sn_bignum)?
    };
    cert_builder.set_serial_number(&serial_number)?;

    let issuer_name = {
        let mut issuer_name_builder = openssl::x509::X509NameBuilder::new()?;
        issuer_name_builder.append_entry_by_text("C", "US")?;
        issuer_name_builder.append_entry_by_text("ST", "Texas")?;
        issuer_name_builder.append_entry_by_text("L", "Austin")?;
        issuer_name_builder.append_entry_by_text("O", "Veracruz")?;
        issuer_name_builder.append_entry_by_text("OU", "Proxy")?;
        issuer_name_builder.append_entry_by_text("CN", "VeracruzProxyServer")?;
        issuer_name_builder.build()
    };
    cert_builder.set_issuer_name(&issuer_name)?;

    cert_builder.set_subject_name(csr.subject_name())?;
    cert_builder.set_pubkey(csr.public_key()?.as_ref())?;

    let mut alt_name_extension = openssl::x509::extension::SubjectAlternativeName::new();
    alt_name_extension.dns("RootEnclave.dev");
    let built_extension = alt_name_extension.build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(built_extension)?;

    let constraints_extension = openssl::x509::extension::BasicConstraints::new().critical().ca().pathlen(1).build()?;
    cert_builder.append_extension(constraints_extension)?;

    let key_pem = {
        let mut f = std::fs::File::open("../test-collateral/CAKey.pem")?;
        let mut buffer: Vec<u8> = Vec::new();
        f.read_to_end(&mut buffer)?;
        buffer
    };

    let private_key = openssl::pkey::PKey::private_key_from_pem(&key_pem)?;
    cert_builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;
    Ok(cert_builder.build())
}
