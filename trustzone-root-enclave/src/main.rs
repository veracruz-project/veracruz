//! The TrustZone root enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![no_main]
#![crate_name = "trustzone_root_enclave"]
#![feature(rustc_private)]

use lazy_static::lazy_static;
use libc;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
    ErrorKind, Parameters,
};
use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key,
};
use ring::{digest, rand::{ SecureRandom, SystemRandom}, signature };
use std::{convert::{TryFrom, TryInto}, io::Write};
use std::collections::HashMap;
use std::sync::atomic::{ AtomicU32, Ordering};
use veracruz_utils::platform::tz::root_enclave_opcode::TrustZoneRootEnclaveOpcode;
use veracruz_utils::csr;

lazy_static! {
    static ref DEVICE_PRIVATE_KEY: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
    static ref DEVICE_ID: std::sync::Mutex<Option<i32>> = std::sync::Mutex::new(None);
    // Yes, I'm doing what you think I'm doing here. Each instance of the TrustZone root enclave
    // will have the same private key. Yes, I'm embedding that key in the source
    // code. I could come up with a complicated system for auto generating a key
    // for each instance, and then populate the device database with they key.
    // That's what needs to be done if you want to productize this.
    // That's not what I'm going to do for this research project
    static ref ROOT_PRIVATE_KEY: Vec<u8> = vec![
        0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
        0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x5, 0x76, 0xa1, 0x44,
    ];
    // Note: the following static value should not be a static value
    // It should be the hash value of the current program (trustzone-root-enclave), and it
    // should be retrieved from the OS, not from itself (bootstrapping trust
    // kinda doesn't work that way).
    // However, OPTEE doesn't really provide this feature at the moment,
    // therefore we've got this dirty hack here that COMPLETELY COMPROMISES
    // the security of the system. THIS IS FOR DEMONSTRATION PURPOSES ONLY
    // AND IS NOT SECURE IN ANY MEANINGFUL WAY!
    static ref TRUSTZONE_ROOT_ENCLAVE_HASH: Vec<u8> = vec![
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe,
    ];
    static ref RUNTIME_MANAGER_HASH: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
    /// Mutex to hold the certificate chain provided by the Proxy Attestation Service
    /// after a successful native attestation
    static ref CERT_CHAIN: std::sync::Mutex<Option<(std::vec::Vec<u8>, std::vec::Vec<u8>)>> = std::sync::Mutex::new(None);
    /// A monotonically increasing value to keep track of which challenge value was sent to which compute enclave
    static ref CHALLENGE_ID: AtomicU32 = AtomicU32::new(0);
    /// A hash map for storing challenge values associated with their challenge_id
    static ref CHALLENGE_HASH: std::sync::Mutex<HashMap<u32, Vec<u8>>> =
        std::sync::Mutex::new(HashMap::new());
}

#[ta_create]
fn create() -> optee_utee::Result<()> {
    trace_println!("trustzone-root-enclave:create");

    let device_private_key = {
        let rng = SystemRandom::new();
        // ECDSA prime256r1 generation.
        let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .map_err(|err| {
            trace_println!("Error generating PKCS-8:{:?}", err);
            ErrorKind::TargetDead
        })?;
        pkcs8_bytes.as_ref().to_vec()
    };
    {
        let mut dpk_guard = DEVICE_PRIVATE_KEY
            .lock()
            .map_err(|_| ErrorKind::TargetDead)?;
        *dpk_guard = Some(device_private_key.clone());
    }

    return Ok(());
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> optee_utee::Result<()> {
    trace_println!("trustzone-root-enclave:open_session");
    return Ok(());
}

#[ta_close_session]
fn close_session() {
    trace_println!("trustzone-root-enclave:close_session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("trustzone-root-enclave:destroy");
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> optee_utee::Result<()> {
    trace_println!("trustzone-root-enclave:invoke_comand");
    let cmd = TrustZoneRootEnclaveOpcode::try_from(cmd_id).map_err(|_| ErrorKind::BadParameters)?;
    match cmd {
        TrustZoneRootEnclaveOpcode::GetFirmwareVersionLen => {
            trace_println!("trustzone-root-enclave::invoke_command GetFirmwareVersionLen");
            let mut values = unsafe {
                params.0.as_value().map_err(|err| {
                println!("trustzone-root-enclave::invoke_command TrustZoneRootEnclaveOpcode::GetFirmwareVersionLen failed to get params.0:{:?}", err);
                ErrorKind::Unknown
            })?
            };
            let version = env!("CARGO_PKG_VERSION");
            values.set_a(version.len() as u32);
        }
        TrustZoneRootEnclaveOpcode::GetFirmwareVersion => {
            trace_println!("trustzone-root-enclave::invoke_command GetFirmwareVersion");
            let mut p0 = unsafe {
                params.0.as_memref().map_err(|err| {
                println!("trustzone-root-enclave::invoke_command TrustZoneRootEnclaveOpcode::GetFirmwareVersion failed to get params.0.as_memref:{:?}", err);
                ErrorKind::Unknown
            })?
            };
            let version = env!("CARGO_PKG_VERSION");
            p0.buffer().write(&version.as_bytes()).map_err(|err| {
                println!("trustzone-root-enclave::invoke_command TrustZoneRootEnclaveOpcode::GetFirmwareVersion failed to write to buffer:{:?}", err);
                ErrorKind::Unknown
            })?;
        }
        TrustZoneRootEnclaveOpcode::SetRuntimeManagerHashHack => {
            // This Opcode allows the non-secure world to set the hash value
            // for the Runtime Manager TA that is returned in the Proxy Attestation
            // token. Of course, THIS IS INCREDIBLY INSECURE, and only exists
            // because at the moment, OPTEE does not provide a way for one TA
            // to reliably get the hash of another TA.
            // THIS IS A DIRTY HACK AND COMPROMISES THE SECURITY OF THE ENTIRE
            // SYSTEM AND IS ONLY HERE TO ALLOW FOR DEMONSTRATIONS
            trace_println!("trustzone-root-enclave::invoke_command SetRuntimeManagerHashHack");
            let hash_value = unsafe {
                let mut memref = params.0.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command::SetRuntimeManagerHashHack failed to get params.0 as mem_ref:{:?}", err);
                    ErrorKind::BadParameters
                })?;
                memref.buffer().to_vec()
            };
            let mut rmh_guard = RUNTIME_MANAGER_HASH.lock().map_err(|err| {
                trace_println!("trustzone-root-enclave::invoke_command::SetRuntimeManagerHashHack failed to obtain lock on RUNTIME_MANAGER_HASH:{:?}", err);
                ErrorKind::TargetDead
            })?;
            *rmh_guard = Some(hash_value);
        }
        TrustZoneRootEnclaveOpcode::NativeAttestation => {
            // p0 - input: a: device_id, output: a: token Length output, b: CSR length
            // p1 - challenge
            // p2 - token buffer
            // p3 - CSR buffer
            trace_println!("trustzone-root-enclave::invoke_command NativeAttestation Opcode started");

            let mut values = unsafe {
                params.0.as_value().map_err(|err| {
                    trace_println!(
                        "trustzone-root-enclave::NativeAttestation failed to extract values from parameters:{:?}",
                        err
                    );
                    ErrorKind::Unknown
                })?
            };
            let device_id: i32 = values.a().try_into().map_err(|err| {
                trace_println!(
                    "trustzone-root-enclave::invoke_command NativeAttestation failed to convert a into i32:{:?}",
                    err
                );
                ErrorKind::Unknown
            })?;

            let challenge = unsafe {
                let mut memref = params.1.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command::NativeAttestation failed to get params.1 as mem_ref:{:?}", err);
                    ErrorKind::BadParameters
                })?;
                memref.buffer().to_vec()
            };

            let mut token_buf = unsafe {
                params.2.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::NativeAttestation failed to extract token_buf from parameters:{:?}", err);
                    ErrorKind::Unknown
                })?
            };

            let mut csr_buf = unsafe {
                params.3.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::NativeAttestation failed to extrac public key buffer from parameters:{:?}", err);
                    ErrorKind::Unknown
                })?
            };

            let dpk_ring = {
                let dpk = device_private_key()
                    .map_err(|err| {
                        trace_println!("trustzon-root-enclave::NativeAttestation failed to get device private_key:{:?}", err);
                        ErrorKind::Unknown
                    })?;
                signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &dpk)
                    .map_err(|err| {
                        trace_println!("trustzone-root-enclave::NativeAttestation failed to generate EcdsaKeyPair from device private key:{:?}", err);
                        ErrorKind::Unknown
                    })?
            };

            let csr = csr::generate_csr(&csr::ROOT_ENCLAVE_CSR_TEMPLATE, &dpk_ring)
                .map_err(|err| {
                    trace_println!("trustzone-root-enclave::NativeAttestation failed to generate csr:{:?}", err);
                    ErrorKind::Unknown
                })?;
            trace_println!("trustzone-root-enclave::invoke_command calling native_attestation function");
            let token = native_attestation(device_id, &challenge, &csr).map_err(|err| {
                trace_println!(
                    "trustzone-root-enclave::invoke_command call to native_attestation failed:{:?}",
                    err
                );
                ErrorKind::TargetDead
            })?;
            trace_println!("trustzone-root-enclave::invoke_command returned from native_attestation function");
            token_buf.buffer().write(&token).map_err(|err| {
                trace_println!(
                    "trustzone-root-enclave::NativeAttestation failed to place token in token_buf:{:?}",
                    err
                );
                ErrorKind::Unknown
            })?;

            trace_println!("trustzone-root-enclave::invoke_command setting token.len:{:}", token.len());
            values.set_a(token.len() as u32);

            csr_buf.buffer().write(&csr).map_err(|err| {
                trace_println!(
                    "trustzone-root-enclave::NativeAttestation failed to place CSR in csr_buf:{:?}",
                    err
                );
                ErrorKind::Unknown
            })?;
            values.set_b(csr.len() as u32);
        }
        TrustZoneRootEnclaveOpcode::CertificateChain => {
            // p0 - root certificate input
            // p1 - Root Enclave certificate input
            // p2-p3 - NULL
            trace_println!("trustzone-root-enclave::invoke_command CertificateChain Opcode started");
            let root_certificate = unsafe {
                let mut memref = params.0.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command CertificateChain failed to get params.0 as memref{:?}", err);
                    ErrorKind::BadParameters
                })?;
                memref.buffer().to_vec()
            };
            let root_enclave_certificate = unsafe {
                let mut memref = params.1.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command CertificateChain failed to get params.1 as memref:{:?}", err);
                    ErrorKind::BadParameters
                })?;
                memref.buffer().to_vec()
            };
            let mut cert_chain_guard = CERT_CHAIN.lock()
                .map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command CertificateChain failed to obtain lock on CERT_CHAIN:{:?}", err);
                    ErrorKind::Unknown
                })?;
            match &*cert_chain_guard {
                Some(_) => {
                    panic!("Unhandled. CERT_CHAIN is not None.");
                }
                None => {
                    *cert_chain_guard = Some((root_enclave_certificate, root_certificate));
                }
            }
        }
        TrustZoneRootEnclaveOpcode::StartLocalAttestation => {
            // p0 - challenge output
            // p1.a - challenge ID output value
            // p2-p3 - NULL
            let challenge_id = CHALLENGE_ID.fetch_add(1, Ordering::SeqCst);
            let mut challenge_buffer = unsafe {
                let mut memref = params.0.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command StartLocalAttestation failed to get params.0 as memref:{:?}", err);
                    ErrorKind::BadParameters
                })?;
                memref.buffer().to_vec()
            };
            let mut values = unsafe {
                params.1.as_value().map_err(|err| {
                    trace_println!(
                        "trustzone-root-enclave::invoke_command StartLocalAttestation failed to extract values from params.1:{:?}",
                        err
                    );
                    ErrorKind::Unknown
                })?
            };
            // fill challenge buffer with random data
            SystemRandom::new().fill(&mut challenge_buffer)
                .map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command StartLocalAttestation failed to fill challenge_buffer:{:?}", err);
                    ErrorKind::Unknown
                })?;

            // save the challenge_id, challenge in the hash
            {
                let mut ch_guard = CHALLENGE_HASH.lock()
                    .map_err(|err| {
                        trace_println!("trustzone-root-enclave::invoke_command StartLocalAttestation failed to obtain lock on CHALLENGE_HASH:{:?}", err);
                        ErrorKind::Unknown
                    })?;
                ch_guard.insert(challenge_id, challenge_buffer);
            }

            // return the challenge_id
            values.set_a(challenge_id);
        }
        // TrustZoneRootEnclaveOpcode::FinishLocalAttestation => {
        //     TODO: Implement this
        // }
        TrustZoneRootEnclaveOpcode::ProxyAttestation => {
            // p0 - csr input
            // p1 -a: challenge id input
            // p2 - cert_chain_buffer output
            // p3 - cert_lengths - output

            let csr = unsafe {
                let mut memref = params.0.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to get params.0 as memref:{:?}", err);
                    ErrorKind::BadParameters
                })?;
                memref.buffer().to_vec()
            };
            let challenge_id = unsafe {
                params.1.as_value()
                    .map_err(|e| {
                        trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to get params.1 as value:{:?}", e);
                        ErrorKind::BadParameters
                    })?
                    .a()
            };
            let mut cert_chain_buffer = unsafe {
                let memref = params.2.as_memref().map_err(|err| {
                    trace_println!(
                        "trustzone-root-enclave::invoke_command failed to get memref from params.2:{:?}",
                        err
                    );
                    ErrorKind::TargetDead
                })?;
                memref
            };
            // Note: we really want cert_lengths_buffer to be a vec of u32,
            // but the optee-utee library doesn't support that.
            // instead, we are going to get it as u8, collect the data for it
            // in another vec of u32, and then transmute that vec and then copy
            let mut cert_lengths_buffer = unsafe {
                let memref = params.3.as_memref().map_err(|err| {
                    trace_println!(
                        "trustzone-root-enclave::invoke_command failed to get memref from params.3:{:?}",
                        err
                    );
                    ErrorKind::TargetDead
                })?;
                memref
            };

            // look up the challenge using challenge_id
            // NOTE: In a system that supported local attestation, We would 
            // compare the expected challenge against a challenge value provided
            // in a token. We don't have that, so we won't do the comparison.
            // One way around this: place the challenge in the CSR as an extension,
            // then extract it and compare. We are not doing that now. TODO
            let _expected_challenge = {
                let mut ch_guard = CHALLENGE_HASH.lock()
                    .map_err(|err| {
                        trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to obtain lock on CHALLENGE_HASH:{:?}", err);
                        ErrorKind::TargetDead
                    })?;
                ch_guard.remove(&challenge_id).ok_or(ErrorKind::BadParameters)?
            };

            // In world where TrustZone had local attestation (not our platform)
            // the hash of the runtime_manager enclave would be sent in a local
            // attestation token, or at least provided to this call by TF-A
            // We don't have that, so we have our own call (TrustZoneRootEnclaveOpcode::SetRuntimeManagerHashHack)
            // that populates RUNTIME_MANAGER_HASH for us. This is a dirty
            // hack.
            let runtime_manager_hash = {
                let rmh = RUNTIME_MANAGER_HASH.lock()
                    .map_err(|err| {
                        trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to obtain lock on RUNTIME_MANAGER_HASH:{:?}", err);
                        ErrorKind::TargetDead
                    })?;
                match &*rmh {
                    Some(hash) => hash.clone(),
                    None => return Err(optee_utee::Error::new(ErrorKind::TargetDead)),
                }
            };

            let private_key = {
                let dpk = device_private_key()
                    .map_err(|_| ErrorKind::TargetDead)?;
                signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &dpk)
                    .map_err(|_| ErrorKind::Unknown)?
            };
            // Now that we've "verified" the challenge, convert the CSR to a 
            // certificate
            let mut runtime_manager_cert = 
                veracruz_utils::csr::convert_csr_to_cert(&csr, 
                                                         &veracruz_utils::csr::COMPUTE_ENCLAVE_CERT_TEMPLATE,
                                                         &runtime_manager_hash,
                                                         &private_key)
                    .map_err(|err| {
                        trace_println!("convert_csr_to_cert failed:{:?}", err);
                        ErrorKind::Unknown
                    })?;
            let (mut root_enclave_cert, mut root_cert) = {
                let cc_guard = CERT_CHAIN.lock()
                    .map_err(|_| ErrorKind::TargetDead)?;
                match &*cc_guard {
                    Some((re_cert, r_cert)) => (re_cert.clone(), r_cert.clone()),
                    None => return Err(optee_utee::Error::new(ErrorKind::BadParameters)),
                }
            };

            // create a buffer to aggregate the certificates
            let mut temp_cert_buf: Vec<u8> = Vec::new();
            let mut temp_cert_lengths: Vec<u32> = Vec::new();

            temp_cert_lengths.push(runtime_manager_cert.len() as u32);
            temp_cert_buf.append(&mut runtime_manager_cert);

            temp_cert_lengths.push(root_enclave_cert.len() as u32);
            temp_cert_buf.append(&mut root_enclave_cert);

            temp_cert_lengths.push(root_cert.len() as u32);
            temp_cert_buf.append(&mut root_cert);

            cert_chain_buffer.buffer().write(&temp_cert_buf).map_err(|e| {
                trace_println!("runtime_manager_trustzone::invoke_command ProxyAttestation failed to write buffer {:?}",
                    e);
                ErrorKind::TargetDead
            })?;

            // since our target buffer is vec<u8>, and our source is vec<u32>,
            // we need to transmute the source before the copy
            let temp_cert_lengths_u8: Vec<u8> = veracruz_utils::platform::tz::transmute_from_u32(&temp_cert_lengths);
            cert_lengths_buffer.buffer().write(&temp_cert_lengths_u8)
                .map_err(|e| {
                    trace_println!("runtime_manager_trustzone::invoke_command ProxyAttestation failed to write buffer {:?}",
                        e);
                    ErrorKind::TargetDead
            })?;
        }
    }
    trace_println!("trustzone-root-enclave::invoke_command done");
    return Ok(());
}

fn native_attestation(device_id: i32, challenge: &Vec<u8>, csr: &Vec<u8>) -> Result<Vec<u8>, String> {
    let mut root_key_handle: u16 = 0;
    let status = unsafe {
        psa_initial_attest_load_key(
            ROOT_PRIVATE_KEY.as_ptr(),
            ROOT_PRIVATE_KEY.len() as u64,
            &mut root_key_handle,
        )
    };
    if status != 0 {
        return Err(format!(
            "trustzone-root-enclave::create psa_initial_attest_load key failed with code:{:}",
            status
        ))?;
    }

    // Save the device_id
    {
        let mut di_guard = DEVICE_ID.lock().map_err(|err| {
            format!(
                "trustzone-root-enclave::native_attestation failed to obtain lock on DEVICE_ID:{:?}",
                err
            )
        })?;
        *di_guard = Some(device_id);
    }

    let csr_hash: Vec<u8> = digest::digest(&digest::SHA256, csr).as_ref().to_vec();

    let mut trustzone_root_enclave_hash: [u8; 32] = [0; 32];
    trustzone_root_enclave_hash.clone_from_slice(&TRUSTZONE_ROOT_ENCLAVE_HASH[0..32]);
    let mut token_buffer: Vec<u8> = Vec::with_capacity(1024); // TODO: Don't do this
    let mut token_size: u64 = 0;
    let status = unsafe {
        psa_initial_attest_get_token(
            &trustzone_root_enclave_hash as *const u8,
            trustzone_root_enclave_hash.len() as u64,
            csr_hash.as_ptr() as *const u8,
            csr_hash.len() as u64,
            std::ptr::null() as *const u8,
            0,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token_buffer.as_mut_ptr() as *mut u8,
            token_buffer.capacity() as u64,
            &mut token_size as *mut u64,
        )
    };
    if status != 0 {
        return Err(format!(
            "trustzone-root-enclave::native_attestation psa_initial_attest_get_token failed with error code:{:}",
            status
        ));
    }
    unsafe { token_buffer.set_len(token_size as usize) };
    Ok(token_buffer.clone())
}

fn device_private_key() -> Result<Vec<u8>, String> {
    let dpk_guard = DEVICE_PRIVATE_KEY.lock().map_err(|err| {
        format!(
            "trustzone-root-enclave::device_private_key failed to obtain lock on DEVICE_PRIVATE_KEY:{:?}",
            err
        )
    })?;
    match &*dpk_guard {
        Some(dpk) => Ok(dpk.clone()),
        None => return Err(format!("trustzone-root-enclave::device_private_key Device private key is not populated?")),
    }
}

// NOTE: fix a mystery where a bcmp function implementation is required for compiling the
// trustzone-root-enclave which optee does not provide.
// Have tried to patch in the rust/libc but it will introduce double implementation.
// TODO: Why does it happen in the first place???
#[allow(non_camel_case_types)]
type c_int = i32;
#[allow(non_camel_case_types)]
type size_t = usize;
use libc::c_void;

extern "C" {
    pub fn memcmp(cx: *const c_void, ct: *const c_void, n: size_t) -> c_int;
}

#[no_mangle]
extern "C" fn bcmp(cx: *const c_void, ct: *const c_void, n: size_t) -> c_int {
    unsafe { memcmp(cx, ct, n) }
}

// TA configurations
const TA_FLAGS: u32 = optee_utee_sys::TA_FLAG_SINGLE_INSTANCE
    | optee_utee_sys::TA_FLAG_MULTI_SESSION
    | optee_utee_sys::TA_FLAG_INSTANCE_KEEP_ALIVE;
const TA_DATA_SIZE: u32 = 1024 * 1024;
const TA_STACK_SIZE: u32 = 512 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"TrustZone (TZ) root enclave TA for Veracruz\0";
const EXT_PROP_VALUE_1: &[u8] = b"TrustZone (TZ) root enclave TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"JL\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
