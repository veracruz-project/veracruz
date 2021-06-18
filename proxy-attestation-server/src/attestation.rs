//! Attestation
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "psa")]
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
        #[cfg(feature = "psa")]
        "psa" => psa::start(&firmware_version, device_id),
        #[cfg(feature = "nitro")]
        "nitro" => nitro::start(&firmware_version, device_id),
        _ => Err(ProxyAttestationServerError::UnknownAttestationTokenError),
    }
}

fn convert_csr_to_certificate(csr_der: &[u8]) -> Result<openssl::x509::X509, ProxyAttestationServerError> {
    let csr = openssl::x509::X509Req::from_der(&csr_der)?;
    // first, verify the signature on the CSR
    let public_key = csr.public_key()?;
    let verify_result = csr.verify(&public_key)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate csr.verify failed:{:?}", err);
            err
        })?;

    if !verify_result {
        println!("proxy_attestation_server::convert_csr_to_certificate verify of CSR failed");
        return Err(ProxyAttestationServerError::CsrVerifyError);
    }
    let mut cert_builder = openssl::x509::X509Builder::new()
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate X509Builder::new failed:{:?}", err);
            err
        })?;
    cert_builder.set_version(2)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_version failed:{:?}", err);
            err
        })?;
    let now = openssl::asn1::Asn1Time::days_from_now(0)
                .map_err(|err| {
                    println!("proxy-attestation-server::attestation::convert_csr_to_certificate days_from_now failed:{:?}", err);
                    err
                })?;
    cert_builder.set_not_before(&now)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_not_before failed:{:?}", err);
            err
        })?;

    // TODO: Make this configurable
    let expiry =openssl::asn1::Asn1Time::days_from_now(1)
                    .map_err(|err| {
                        println!("proxy-attestation-server::attestation::convert_csr_to_certificate days_from_now failed:{:?}", err);
                        err
                    })?;
    cert_builder.set_not_after(&expiry)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_not_after failed:{:?}", err);
            err
        })?;

    // TODO: Do we want to manage serial numbers? Right now, they are all the same
    let serial_number = {
        let sn_bignum = openssl::bn::BigNum::from_u32(23)
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::convert_csr_to_certificate from_u32 failed:{:?}", err);
                err
            })?;
        openssl::asn1::Asn1Integer::from_bn(&sn_bignum)
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::convert_csr_to_certificate from_bn failed:{:?}", err);
                err
            })?
    };
    cert_builder.set_serial_number(&serial_number)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_serial_number failed:{:?}", err);
            err
        })?;

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
    cert_builder.set_issuer_name(&issuer_name)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_issuer_name failed:{:?}", err);
            err
        })?;

    cert_builder.set_subject_name(csr.subject_name())
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_subject_name failed:{:?}", err);
            err
        })?;
    cert_builder.set_pubkey(csr.public_key()?.as_ref())
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_pubkey failed:{:?}", err);
            err
        })?;

    let mut alt_name_extension = openssl::x509::extension::SubjectAlternativeName::new();
    alt_name_extension.dns("RootEnclave.dev");
    let built_extension = alt_name_extension.build(&cert_builder.x509v3_context(None, None))
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate alt_name_extension.build failed:{:?}", err);
            err
        })?;
    cert_builder.append_extension(built_extension)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate append_extension failed:{:?}", err);
            err
        })?;

    let constraints_extension = openssl::x509::extension::BasicConstraints::new().critical().ca().pathlen(1).build()
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate BasicConstraints::new failed:{:?}", err);
            err
        })?;
    cert_builder.append_extension(constraints_extension)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate append_extension failed:{:?}", err);
            err
        })?;

    let key_pem = {
        let mut f = std::fs::File::open("../test-collateral/CAKey.pem")
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::convert_csr_to_certificate open of file failed:{:?}", err);
                err
            })?;
        let mut buffer: Vec<u8> = Vec::new();
        f.read_to_end(&mut buffer)
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::convert_csr_to_certificate read_to_end failed:{:?}", err);
                err
            })?;
        buffer
    };

    let private_key = openssl::pkey::PKey::private_key_from_pem(&key_pem)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate private_key_from_pem failed:{:?}", err);
            err
        })?;
    cert_builder.sign(&private_key, openssl::hash::MessageDigest::sha256())
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate cert_builder.sign failed:{:?}", err);
            err
        })?;
    Ok(cert_builder.build())
}
