//! The Veracruz proxy attestation server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::attestation;
#[cfg(feature = "nitro")]
use crate::attestation::nitro;
#[cfg(any(feature = "linux", feature = "icecap"))]
use crate::attestation::psa;
use crate::error::*;
use actix_web::{dev::Server, middleware, web, App, HttpServer, HttpRequest, HttpResponse, Error};
use lazy_static::lazy_static;
use std::{
    net::ToSocketAddrs,
    path,
    sync::atomic::{AtomicBool, Ordering},
};
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder, X509};

lazy_static! {
    pub static ref DEBUG_MODE: AtomicBool = AtomicBool::new(false);
}

/// just to test
async fn index(req: HttpRequest) -> Result<HttpResponse, Error> {
    println!("{:?}", req);
    Ok(HttpResponse::Ok()
        .content_type("text/plain")
        .body("Welcome!"))
}

#[allow(unused)]
async fn psa_router(
    psa_request: web::Path<String>,
    input_data: String,
) -> ProxyAttestationServerResponder {
    #[cfg(any(feature = "linux", feature = "icecap"))]
    if psa_request.into_inner().as_str() == "AttestationToken" {
        psa::attestation_token(input_data)
    } else {
        Err(ProxyAttestationServerError::UnsupportedRequestError)
    }
    #[cfg(not(any(feature = "linux", feature = "icecap")))]
    Err(ProxyAttestationServerError::UnimplementedRequestError)
}

#[allow(unused)]
async fn nitro_router(
    nitro_request: web::Path<String>,
    input_data: String,
) -> ProxyAttestationServerResponder {
    #[cfg(feature = "nitro")]
    {
        let inner = nitro_request.into_inner();
        if inner.as_str() == "AttestationToken" {
            nitro::attestation_token(input_data)
        } else {
            println!(
                "proxy-attestation-server::nitro_router returning unsupported with into_inner:{:?}",
                inner.as_str()
            );
            Err(ProxyAttestationServerError::UnsupportedRequestError)
        }
    }
    #[cfg(not(feature = "nitro"))]
    Err(ProxyAttestationServerError::UnimplementedRequestError)
}

// Generate a certificate signing request using CA private key
fn generate_csr(key: PKey<Private>) -> Result<X509Req, ProxyAttestationServerError> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&key)?;
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("CN", "localhost")?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;
    req_builder.sign(&key, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

// Convert CSR to an X509 certificate and sign it
fn convert_csr_to_certificate_sign(csr: X509Req, ca_cert: X509, ca_key: PKey<Private>) -> Result<X509, ProxyAttestationServerError> {
    // first, verify the signature on the CSR
    let public_key = csr.public_key()?;
    let verify_result = csr.verify(&public_key)?;
    if !verify_result {
        println!("proxy_attestation_server::convert_csr_to_certificate_sign verify of CSR failed");
        return Err(ProxyAttestationServerError::CsrVerifyError);
    }

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(csr.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(csr.public_key()?.as_ref())?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    // need to double check.. 
    let not_after = Asn1Time::days_from_now(356)?;
    cert_builder.set_not_after(&not_after)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert_builder.x509v3_context(Some(&ca_cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    cert_builder.sign(&ca_key, MessageDigest::sha256())?;
    Ok(cert_builder.build())
}

pub fn server<U, P1, P2>(
    url: U,
    ca_cert_path: P1,
    ca_key_path: P2,
    debug: bool,
) -> Result<Server, String>
where
    U: ToSocketAddrs,
    P1: AsRef<path::Path>,
    P2: AsRef<path::Path>,
{
    if debug {
        DEBUG_MODE.store(true, Ordering::SeqCst);
    }
    crate::attestation::load_ca_certificate(ca_cert_path).map_err(|err| {
        format!(
            "proxy-attestation-server::server::server load_ca_certificate returned an error:{:?}",
            err
        )
    })?;
    crate::attestation::load_ca_key(ca_key_path).map_err(|err| {
        format!(
            "proxy-attestation-server::server::server load_ca_key returned an error:{:?}",
            err
        )
    })?;
    let ca_cert_der = crate::attestation::get_ca_certificate().map_err(|err| {
        format!(
            "proxy-attestation-server::server::server get_ca_certificate returned an error:{:?}",
            err
        )
    })?;
    let ca_cert = openssl::x509::X509::from_der(&ca_cert_der).map_err(|err| {
        format!(
            "proxy-attestation-server::server::server get_ca_certificate returned an error:{:?}",
            err
        )
    })?;
    let private_key = crate::attestation::get_ca_key().map_err(|err| {
        format!(
            "proxy-attestation-server::server::server get_ca_key returned an error:{:?}",
            err
        )
    })?;

    let csr = generate_csr(private_key.clone()).map_err(|err| {
        format!(
            "proxy-attestation-server::server::generate_csr returned an error:{:?}",
            err
        )
    })?;
    let cert = convert_csr_to_certificate_sign(csr, ca_cert, private_key.clone()).unwrap();
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

    builder.set_certificate(&cert).unwrap();
    builder.set_private_key(&private_key).unwrap();
    //builder.set_private_key_file("key.pem", SslFiletype::PEM).unwrap();
    //builder.set_certificate_chain_file("cert.pem").unwrap();
   
    let server = HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .service(web::resource("/index.html").to(index))
            .route("/Start", web::post().to(attestation::start))
            .route("/PSA/{psa_request}", web::post().to(psa_router))
            .route("/Nitro/{nitro_request}", web::post().to(nitro_router))
    })
    .bind_openssl(url, builder)
    .map_err(|err| format!("binding error: {:?}", err))?
    .run();
    Ok(server)
}