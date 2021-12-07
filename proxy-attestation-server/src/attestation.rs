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

#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(any(feature = "linux", feature = "icecap"))]
pub mod psa;

use crate::error::*;
use lazy_static::lazy_static;
use std::{
    io::Read,
    path,
    sync::atomic::{AtomicI32, Ordering},
};
use veracruz_utils::VERACRUZ_RUNTIME_HASH_EXTENSION_ID;

use openssl;

lazy_static! {
    static ref DEVICE_ID: AtomicI32 = AtomicI32::new(1);
    static ref CA_CERT_DER: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
    static ref CA_KEY_PKEY: std::sync::Mutex<Option<openssl::pkey::PKey<openssl::pkey::Private>>> =
        std::sync::Mutex::new(None);
}

/// Reads a PEM certificate from `pem_cert_path`, converts it to DER format,
/// and stores it in CA_CERT_DER for use by the service
pub fn load_ca_certificate<P>(pem_cert_path: P) -> Result<(), ProxyAttestationServerError>
where
    P: AsRef<path::Path>,
{
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

/// Reads a PEM key from `pem_key_path`, converts it to DER format,
/// and stores it in CA_KEY_PKEY for use by the service
pub fn load_ca_key<P>(pem_key_path: P) -> Result<(), ProxyAttestationServerError>
where
    P: AsRef<path::Path>,
{
    let mut f = std::fs::File::open(pem_key_path)
        .map_err(|err| ProxyAttestationServerError::IOError(err))?;
    let mut buffer: Vec<u8> = Vec::new();
    f.read_to_end(&mut buffer)?;
    let key = openssl::pkey::PKey::private_key_from_pem(&buffer)?;
    let mut guard = CA_KEY_PKEY.lock()?;
    match *guard {
        Some(_) => return Err(ProxyAttestationServerError::BadStateError),
        None => {
            *guard = Some(key);
        }
    }
    return Ok(());
}

fn get_ca_key() -> Result<openssl::pkey::PKey<openssl::pkey::Private>, ProxyAttestationServerError>
{
    let guard = CA_KEY_PKEY.lock()?;
    match &*guard {
        None => return Err(ProxyAttestationServerError::BadStateError),
        Some(key) => return Ok(key.clone()),
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
        #[cfg(any(feature = "linux", feature = "icecap"))]
        "psa" => psa::start(&firmware_version, device_id),
        #[cfg(feature = "nitro")]
        "nitro" => nitro::start(&firmware_version, device_id),
        _ => Err(ProxyAttestationServerError::UnknownAttestationTokenError),
    }
}

/// Convert a Certificate Signing Request (CSR) to an X.509 Certificate and
/// sign it
fn convert_csr_to_certificate(
    csr_der: &[u8],
    is_ca: bool,
    enclave_hash: &[u8],
) -> Result<openssl::x509::X509, ProxyAttestationServerError> {
    let csr = openssl::x509::X509Req::from_der(csr_der)
        .map_err(|err| {
            print!("proxy-attestation-server::attestation::convert_csr_to_certificate failed to get csr from der:{:?}", err);
            err
        })?;

    // first, verify the signature on the CSR
    let public_key = csr.public_key()?;
    let verify_result = csr.verify(&public_key)?;

    if !verify_result {
        println!("proxy_attestation_server::convert_csr_to_certificate verify of CSR failed");
        return Err(ProxyAttestationServerError::CsrVerifyError);
    }

    let mut cert_builder = openssl::x509::X509Builder::new().map_err(|err| {
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

    // TODO: Currently setting the certificate expiry to a day from now. In the
    // future it would be good to make it configurable (also, 1 day seems a bit
    // long in this context)
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

    // construct and set the issuer name as the subject name of the CA cert
    let issuer_name = {
        let ca_der = get_ca_certificate()
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::convert_csr_to_certificate get_ca_certificate failed:{:?}", err);
                err
            })?;
        let ca_cert = openssl::x509::X509::from_der(&ca_der)?;

        let mut issuer_name_builder = openssl::x509::X509NameBuilder::new()?;
        for entry in ca_cert.subject_name().entries() {
            issuer_name_builder
                .append_entry_by_nid(entry.object().nid(), &entry.data().as_utf8()?)?;
        }
        issuer_name_builder.build()
    };

    cert_builder.set_issuer_name(&issuer_name)
         .map_err(|err| {
             println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_issuer_name failed:{:?}", err);
             err
         })?;

    // set the subject name of the certificate to the subject name from the CSR
    cert_builder.set_subject_name(csr.subject_name())
         .map_err(|err| {
             println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_subject_name failed:{:?}", err);
             err
         })?;
    // set the public key of the certificate to the public key from the CSR
    cert_builder.set_pubkey(csr.public_key()?.as_ref())
         .map_err(|err| {
             println!("proxy-attestation-server::attestation::convert_csr_to_certificate set_pubkey failed:{:?}", err);
             err
         })?;

    // The alt-name extension is required by our client. It basically sets the
    // URL that the certificat is valid for.
    let mut alt_name_extension = openssl::x509::extension::SubjectAlternativeName::new();

    alt_name_extension.dns("ComputeEnclave.dev");
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

    // setting the basic constraints extension to 'critical' - meaning required,
    // to 'ca' meaning the certificate is a CA certificate
    let mut constraints_extension = openssl::x509::extension::BasicConstraints::new();
    constraints_extension.critical();
    constraints_extension.pathlen(1);
    if is_ca {
        constraints_extension.ca();
    }
    let built_constraints_extension = constraints_extension.build()
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate BasicConstraints::new failed:{:?}", err);
            err
        })?;
    cert_builder.append_extension(built_constraints_extension)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate append_extension failed:{:?}", err);
            err
        })?;

    // Add our custom extension to the certificate that contains the hash of the enclave
    let extension_name = format!(
        "{}.{}.{}.{}",
        VERACRUZ_RUNTIME_HASH_EXTENSION_ID[0],
        VERACRUZ_RUNTIME_HASH_EXTENSION_ID[1],
        VERACRUZ_RUNTIME_HASH_EXTENSION_ID[2],
        VERACRUZ_RUNTIME_HASH_EXTENSION_ID[3]
    );
    let extension_value = format!("DER:{}", hex::encode(enclave_hash));
    let custom_extension = openssl::x509::X509Extension::new(None, None, &extension_name, &extension_value)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate X509Extension::new failed:{:?}", err);
            err
        })?;

    cert_builder.append_extension(custom_extension)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate append_extension for custom extension failed: {:?}", err);
            err
        })?;

    let private_key = get_ca_key()?;

    // sign the certificate
    cert_builder.sign(&private_key, openssl::hash::MessageDigest::sha256())
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::convert_csr_to_certificate cert_builder.sign failed:{:?}", err);
            err
        })?;

    // build the final certificate and return it
    Ok(cert_builder.build())
}
