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
    psa_initial_attest_get_token, psa_initial_attest_load_key, t_cose_sign1_get_verification_pubkey,
};
use ring;
use std::convert::TryInto;
use std::io::Write;
use veracruz_utils::TrustZoneRootEnclaveOpcode;

lazy_static! {
    static ref DEVICE_PRIVATE_KEY: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
    static ref DEVICE_PUBLIC_KEY: std::sync::Mutex<Option<Vec<u8>>> =
        std::sync::Mutex::new(None);
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
    static ref TrustZone_ROOT_ENCLAVE_HASH: Vec<u8> = vec![
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe,
    ];
    static ref NATIVE_ATTESTATION_DONE: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
    static ref RUNTIME_MANAGER_HASH: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
}

#[ta_create]
fn create() -> optee_utee::Result<()> {
    trace_println!("trustzone-root-enclave:create");

    let device_private_key = {
        let rng = ring::rand::SystemRandom::new();
        // ECDSA prime256r1 generation.
        let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .map_err(|err| {
            trace_println!("Error generating PKCS-8:{:?}", err);
            ErrorKind::TargetDead
        })?;
        pkcs8_bytes.as_ref()[38..70].to_vec()
    };
    {
        let mut dpk_guard = DEVICE_PRIVATE_KEY
            .lock()
            .map_err(|_| ErrorKind::TargetDead)?;
        *dpk_guard = Some(device_private_key.clone());
    }

    // I've found that the best way to get a key formatted appropriately is to
    // load it into PSA (via the attestation APIs) and then export the public
    // component. It's sort of wonky, but it works. So that's what I'm doing
    // below
    let mut device_key_handle: u16 = 0;
    let status = unsafe {
        psa_initial_attest_load_key(
            device_private_key.as_ptr(),
            device_private_key.len() as u64,
            &mut device_key_handle,
        )
    };
    if status != 0 {
        trace_println!("trustzone-root-enclave::create psa_initial_attest_load_key failed to load device private key with code:{:}", status);
        return Err(optee_utee::Error::new(ErrorKind::TargetDead));
    }
    let mut public_key = std::vec::Vec::with_capacity(128); // TODO: Don't do this
    let mut public_key_size: u64 = 0;
    let status = unsafe {
        t_cose_sign1_get_verification_pubkey(
            device_key_handle,
            public_key.as_mut_ptr() as *mut u8,
            public_key.capacity() as u64,
            &mut public_key_size as *mut u64,
        )
    };
    if status != 0 {
        trace_println!(
            "trustzone-root-enclave::create t_cose_sign1_get_verification_pubkey failed with error code:{:}",
            status
        );
        return Err(optee_utee::Error::new(ErrorKind::TargetDead));
    }
    unsafe { public_key.set_len(public_key_size as usize) };
    {
        let mut dpk_guard = DEVICE_PUBLIC_KEY
            .lock()
            .map_err(|_| ErrorKind::TargetDead)?;
        *dpk_guard = Some(public_key);
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
    let cmd = TrustZoneRootEnclaveOpcode::from_u32(cmd_id).map_err(|_| ErrorKind::BadParameters)?;
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

            let mut pubkey_buf = unsafe {
                params.3.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::NativeAttestation failed to extrac public key buffer from parameters:{:?}", err);
                    ErrorKind::Unknown
                })?
            };
            trace_println!("trustzone-root-enclave::invoke_command calling native_attestation function");
            let token = native_attestation(device_id, &challenge).map_err(|err| {
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
            values.set_b(token.len() as u32);

            let public_key = {
                let dpk_guard = DEVICE_PUBLIC_KEY.lock().map_err(|err| {
                    trace_println!(
                        "trustzone-root-enclave::native_attestation failed to obtain lock on PUBLIC_KEY_HASH:{:}",
                        err
                    );
                    ErrorKind::Unknown
                })?;
                let dpk = dpk_guard.clone().unwrap();
                dpk
            };
            pubkey_buf.buffer().write(&public_key).map_err(|err| {
                trace_println!(
                    "trustzone-root-enclave::NativeAttestation failed to place public key in pubkey_buf:{:?}",
                    err
                );
                ErrorKind::Unknown
            })?;
            values.set_a(public_key.len() as u32);
        }
        TrustZoneRootEnclaveOpcode::ProxyAttestation => {
            // p0 - challenge input
            // p1 - enclave_cert input / TrustZone root enclave Pubkey Output
            // p2 - token output
            // p3 - a: device_id output b:none
            trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation Opcode started");
            let challenge = unsafe {
                trace_println!(
                    "trustzone-root-enclave::invoke_command ProxyAttestation params.0.param_type:{:?}",
                    params.0.param_type
                );
                trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation params.0.raw:");
                trace_println!("\traw.buffer:{:?}", (*params.0.raw).memref.buffer);
                trace_println!("\traw.size: {:?}", (*params.0.raw).memref.size);
                trace_println!("\tparam_type:{:?}", params.0.param_type);
                let mut memref = params.0.as_memref().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to get params.0 as memref:{:?}", err);
                    ErrorKind::BadParameters
                })?;
                memref.buffer().to_vec()
            };
            trace_println!(
                "trustzone-root-enclave::invoke_command ProxyAttestation challenge:{:?}",
                challenge
            );
            trace_println!(
                "trustzone-root-enclave::invoke_command ProxyAttestation challenge.len: {:?}",
                challenge.len()
            );
            let mut cert_pubkey_buffer = unsafe {
                let memref = params.1.as_memref().map_err(|err| {
                    trace_println!(
                        "trustzone-root-enclave::invoke_command failed to get memref from params.1:{:?}",
                        err
                    );
                    ErrorKind::TargetDead
                })?;
                memref
            };
            let cert = cert_pubkey_buffer.buffer().to_vec();
            let mut token_buf = unsafe { params.2.as_memref().unwrap() };

            let token = proxy_attestation(&challenge, &cert).map_err(|err| {
                trace_println!("trustzone-root-enclave::invoke_command proxy_attestation failed:{:?}", err);
                ErrorKind::TargetDead
            })?;
            let mut param3_value = unsafe {
                params.3.as_value().map_err(|err| {
                    trace_println!(
                    "trustzone-root-enclave::invoke_command ProxyAttestation failed to get params.3 as_value:{:?}",
                    err
                );
                    ErrorKind::TargetDead
                })?
            };
            let device_id = {
                let di_guard = DEVICE_ID.lock().map_err(|err| {
                                       trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to get lock on DEVICE_ID:{:?}", err);
                                       ErrorKind::TargetDead
                                   })?;
                di_guard.unwrap()
            };

            let device_public_key = {
                let dpk_guard = DEVICE_PUBLIC_KEY.lock().map_err(|err| {
                    trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to get lock on DEVICE_PUBLIC_KEY:{:?}", err);
                    ErrorKind::TargetDead
                })?;
                (*dpk_guard).clone().unwrap()
            };
            trace_println!(
                "trustzone-root-enclave::invoke_command ProxyAttestation has device_public_key:{:?}",
                device_public_key
            );
            param3_value.set_a(device_id.try_into().map_err(|err| {
                trace_println!("trustzone-root-enclave::invoke_command ProxyAttestation failed to convert device_id into u32:{:?}", err);
                ErrorKind::Unknown
            })?);

            token_buf.buffer().write(&token).map_err(|err| {
                trace_println!(
                    "trustzone-root-enclave::ProxyAttestation failed to place token in token_buf:{:?}",
                    err
                );
                ErrorKind::Unknown
            })?;
            unsafe {
                (*params.2.as_memref().unwrap().raw()).size = token.len().try_into().unwrap()
            };
            cert_pubkey_buffer.buffer().write(&device_public_key).map_err(|err| {
                trace_println!("trustzone-root-enclave::invoke_command::ProxyAttestation faeild to place pubkey in cert_pubkey_buffer:{:?}", err);
                ErrorKind::Unknown
            })?;
            unsafe {
                (*params.1.as_memref().unwrap().raw()).size =
                    device_public_key.len().try_into().unwrap()
            }
        }
    }
    trace_println!("trustzone-root-enclave::invoke_command done");
    return Ok(());
}

fn native_attestation(device_id: i32, challenge: &Vec<u8>) -> Result<Vec<u8>, String> {
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

    let device_public_key_hash: Vec<u8> = {
        let dpk_guard = DEVICE_PUBLIC_KEY.lock().map_err(|err| {
            format!(
                "trustzone-root-enclave::native_attestation failed to obtain lock on PUBLIC_KEY_HASH:{:}",
                err
            )
        })?;
        let dpk = dpk_guard.clone().unwrap();
        trace_println!(
            "trustzone-root-enclave::native_attestation calculating hash of device public key:{:?}",
            dpk
        );
        let pubkey_hash = ring::digest::digest(&ring::digest::SHA256, dpk.as_ref());
        trace_println!(
            "trustzone-root-enclave::native_attestation calculated hash:{:?}",
            pubkey_hash
        );
        pubkey_hash.as_ref().to_vec()
    };

    // let mut identity = TEE_Identity {
    //     login: 0,
    //     uuid: TEE_UUID {
    //         timeLow: 0,
    //         timeMid: 0,
    //         timeHiAndVersion: 0,
    //         clockSeqAndNode: [0; 8],
    //     },
    // };
    // let result = unsafe {
    //     TEE_GetPropertyAsIdentity(
    //         TEE_PROPSET_CURRENT_CLIENT,
    //         "gpd.client.identity\0".as_ptr() as *const u8,
    //         &mut identity,
    //     )
    // };
    // if result != 0 {
    //     return Err(format!(
    //         "trustzone-root-enclave::native_attestation TEE_GetPropertyAsIdentity failed:{:}",
    //         result
    //     ));
    // }

    let mut trustzone_root_enclave_hash: [u8; 32] = [0; 32];
    trustzone_root_enclave_hash.clone_from_slice(&TrustZone_ROOT_ENCLAVE_HASH[0..32]);
    let mut token_buffer: Vec<u8> = Vec::with_capacity(1024); // TODO: Don't do this
    let mut token_size: u64 = 0;
    trace_println!("token_buffer.capacity():{:?}", token_buffer.capacity());
    trace_println!("challenge.len():{:?}", challenge.len());
    let status = unsafe {
        psa_initial_attest_get_token(
            &trustzone_root_enclave_hash as *const u8,
            trustzone_root_enclave_hash.len() as u64,
            device_public_key_hash.as_ptr() as *const u8,
            device_public_key_hash.len() as u64,
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
    trace_println!(
        "trustzone-root-enclave::native_attestation token_buffer value:{:?}",
        token_buffer
    );
    Ok(token_buffer.clone())
}

fn proxy_attestation(challenge: &Vec<u8>, enclave_cert: &Vec<u8>) -> Result<Vec<u8>, String> {
    let device_private_key = {
        let dpk_guard = DEVICE_PRIVATE_KEY.lock().map_err(|err| {
            format!(
                "trustzone-root-enclave::proxy_attestation failed to obtain lock on DEVICE_PRIVATE_KEY:{:?}",
                err
            )
        })?;
        match &*dpk_guard {
            Some(dpk) => dpk.clone(),
            None => return Err(format!("Device private key is not populated?")),
        }
    };
    let mut device_key_handle: u16 = 0;
    let _status = unsafe {
        psa_initial_attest_load_key(
            device_private_key.as_ptr(),
            device_private_key.len() as u64,
            &mut device_key_handle,
        )
    };
    trace_println!("trustzone-root-enclave::proxy_attestation started");
    let runtime_manager_hash = {
        let rmh_guard = RUNTIME_MANAGER_HASH.lock().map_err(|err| {
            format!(
                "trustzone-root-enclave::proxy_attestation failed to obtain lock on RUNTIME_MANAGER_HASH:{:?}",
                err
            )
        })?;
        match &*rmh_guard {
            Some(hash) => hash.clone(),
            None => return Err(format!("trustzone-root-enclave::proxy_attestation RUNTIME_MANAGER_HASH does not contain data and that's a problem")),
        }
    };
    let mut token: Vec<u8> = Vec::with_capacity(2048);
    let mut token_len: u64 = 0;
    let enclave_cert_hash = ring::digest::digest(&ring::digest::SHA256, &enclave_cert);
    let enclave_name = "ac40a0c"; // TODO: Get the real enclave name
    let enclave_name_vec = enclave_name.as_bytes();
    let status = unsafe {
        psa_initial_attest_get_token(
            runtime_manager_hash.as_ptr() as *const u8,
            runtime_manager_hash.len() as u64,
            enclave_cert_hash.as_ref().as_ptr() as *const u8,
            enclave_cert_hash.as_ref().len() as u64,
            enclave_name_vec.as_ptr() as *const u8,
            enclave_name_vec.len() as u64,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token.as_mut_ptr() as *mut u8,
            2048,
            &mut token_len as *mut u64,
        )
    };
    if status != 0 {
        return Err(format!(
            "trustzone-root-enclave::proxy_attestation psa_initial_attest_get_token failed with error code:{:}",
            status
        ));
    }
    unsafe { token.set_len(token_len as usize) };
    trace_println!("trustzone-root-enclave::proxy_attestation token_buffer value:{:?}", token);
    Ok(token.clone())
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
