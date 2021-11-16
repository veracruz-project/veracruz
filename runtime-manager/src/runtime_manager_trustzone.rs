//! Arm TrustZone-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers;
use crate::managers::debug_message;
use libc;
#[cfg(feature = "tz")]
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session,
    ErrorKind, Parameters, Result as OpteeResult, 
};
use std::{
    convert::TryFrom,
    convert::TryInto,
    io::Write,
};

use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, psa_initial_attest_remove_key,
};
use veracruz_utils::platform::tz::runtime_manager_opcode::RuntimeManagerOpcode;

fn print_error_and_return(message: String) -> ErrorKind {
    crate::managers::error_message(message, std::u32::MAX);
    ErrorKind::Unknown
}

use ring::digest;

// Yes, I'm doing what you think I'm doing here. Each instance of the TrustZone runtime manager
// will have the same private key. Yes, I'm embedding that key in the source
// code. I could come up with a complicated system for auto generating a key
// for each instance, and then populate the device database with they key.
// That's what needs to be done if you want to productize this.
// That's not what I'm going to do for this research project
static ROOT_PRIVATE_KEY: [u8; 32] = [
    0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54, 0xd0,
    0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76, 0xa1, 0x44,
];

#[ta_create]
#[cfg(feature = "tz")]
fn create() -> OpteeResult<()> {
    debug_message("runtime_manager_trustzone:create".to_string());
    Ok(())
}

#[ta_open_session]
#[cfg(feature = "tz")]
fn open_session(_params: &mut Parameters) -> OpteeResult<()> {
    debug_message("runtime_manager_trustzone:Open_session".to_string());
    Ok(())
}

#[ta_close_session]
#[cfg(feature = "tz")]
fn close_session() {
    debug_message("runtime_manager_trustzone:Close Session".to_string());
}

#[ta_destroy]
#[cfg(feature = "tz")]
fn destroy() {
    debug_message("runtime_manager_trustzone:destroy".to_string());
}

#[ta_invoke_command]
#[cfg(feature = "tz")]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> OpteeResult<()> {
    debug_message("runtime_manager_trustzone:invoke_command".to_string());
    let cmd = RuntimeManagerOpcode::try_from(cmd_id).map_err(|err| {
        print_error_and_return(format!(
            "runtime_manager_trustzone::invoke_command Failed to convert opcode:{:?} to RuntimeManagerOpcode:{:?}",
            cmd_id, err
        ))
    })?;
    match cmd {
        RuntimeManagerOpcode::Initialize => {
            // p0 - policy input
            debug_message("runtime_manager_trustzone::invoke_command Initialize".to_string());
            let mut memref = unsafe {
                params.0.as_memref().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command Initialize failed to get param.0 as memref {:?}",
                        e
                    ))
                })?
            };
            let buffer = memref.buffer();
            let policy =
                std::str::from_utf8(buffer).map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command Initialize failed to convert from utf8 {:?}",
                        e
                    ))
                })?;

            crate::managers::session_manager::init_session_manager().map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command Initialize {:?}",
                    e
                ))
            })?;
            crate::managers::session_manager::load_policy(&policy).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command load_policy {:?}",
                    e
                ))
            })?;
        }
        RuntimeManagerOpcode::Attestation => {
            // p0 - input: a: device_id, output: a: token Length output, b: CSR length
            // p1 - challenge
            // p2 - token buffer
            // p3 - CSR buffer
            debug_message("RuntimeManagerOpcode::Attestation Attestation Opcode started".to_string());

            let mut values = unsafe {
                params.0.as_value().map_err(|err| {
                    print_error_and_return(format!(
                        "RuntimeManagerOpcode::Attestation failed to extract values from parameters:{:?}",
                        err
                    ))
                })?
            };
            let _device_id: i32 = values.a().try_into().map_err(|err| {
                print_error_and_return(format!(
                    "RuntimeManagerOpcode::Attestation failed to convert a into i32:{:?}",
                    err
                ))
            })?;

            let challenge = unsafe {
                let mut memref = params.1.as_memref().map_err(|err| {
                    print_error_and_return(format!(
                        "RuntimeManagerOpcode::Attestation failed to get params.1 as mem_ref:{:?}",
                        err
                    ))
                })?;
                memref.buffer().to_vec()
            };

            let mut token_buf = unsafe {
                params.2.as_memref().map_err(|err| {
                    print_error_and_return(format!(
                        "RuntimeManagerOpcode::Attestation failed to extract token_buf from parameters:{:?}",
                        err
                    ))
                })?
            };

            let mut csr_buf = unsafe {
                params.3.as_memref().map_err(|err| {
                    print_error_and_return(format!(
                        "RuntimeManagerOpcode::Attestation failed to extrac public key buffer from parameters:{:?}",
                        err
                    ))
                })?
            };

            let csr = crate::managers::session_manager::generate_csr()
                .map_err(|err| {
                    print_error_and_return(format!(
                        "RuntimeManagerOpcode::Attestation failed to generate csr:{:?}",
                        err
                    ))
                })?;

            debug_message(format!("RuntimeManagerOpcode::Attestation calling native_attestation function"));
            let token = native_attestation(&challenge, &csr).map_err(|err| {
                print_error_and_return(format!(
                    "RuntimeManagerOpcode::Attestation call to native_attestation failed:{:?}",
                    err
                ))
            })?;
            debug_message(format!("RuntimeManagerOpcode::Attestation returned from native_attestation function"));
            token_buf.buffer().write(&token).map_err(|err| {
                print_error_and_return(format!(
                    "RuntimeManagerOpcode::Attestation failed to place token in token_buf:{:?}",
                    err
                ))
            })?;

            debug_message(format!("RuntimeManagerOpcode::Attestation setting token.len:{:}", token.len()));
            values.set_a(token.len() as u32);

            csr_buf.buffer().write(&csr).map_err(|err| {
                print_error_and_return(format!(
                    "RuntimeManagerOpcode::Attestation failed to place CSR in csr_buf:{:?}",
                    err
                ))
            })?;
            values.set_b(csr.len() as u32);
        }
        RuntimeManagerOpcode::CertificateChain => {
            // p0 - root certificate
            // p1 - compute_enclave_certificate
            debug_message("runtime_manager_trustzone::invoke_command::CertificateChain started".to_string());
            let root_cert_buffer = unsafe {
                let mut memref = params.0.as_memref().map_err(|err|
                    print_error_and_return(format!("runtime_manager_trustzone::invoke_command::CertificateChain failed to get memref from params.0:{:?}", err))
                )?;
                memref.buffer().to_vec()
            };
            let compute_cert_buffer = unsafe {
                let mut memref = params.1.as_memref().map_err(|err|
                    print_error_and_return(format!("runtime_manager_trustzone::invoke_command::CertificateChain failed to get memref from params.1:{:?}", err))
                )?;
                memref.buffer().to_vec()
            };
            
            let mut certs: Vec<Vec<u8>> = Vec::new();
            certs.push(compute_cert_buffer);
            certs.push(root_cert_buffer);
            managers::session_manager::load_cert_chain(&certs)
                .map_err(|err| print_error_and_return(format!("runtime_manager_trustzone::invoke_command::CertificateChain failed on call to load_cert_chain:{:?}", err)))?;
        }
        RuntimeManagerOpcode::NewTLSSession => {
            debug_message("runtime_manager_trustzone::invoke_command NewTLSSession".to_string());
            let mut values = unsafe {
                params.0.as_value().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command NewTLSSession failed to get param.0 as value {:?}",
                        e
                    ))
                })?
            };
            let local_session_id = managers::session_manager::new_session().map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command NewTLSSession {:?}",
                    e
                ))
            })?;
            values.set_a(local_session_id);
        }
        RuntimeManagerOpcode::CloseTLSSession => {
            debug_message("runtime_manager_trustzone::invoke_command CloseTLSSession".to_string());
            let values = unsafe {
                params.0.as_value().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command CloseTLSSession failed to get param.0 as value {:?}",
                        e
                    ))
                })?
            };
            let session_id = values.a();
            managers::session_manager::close_session(session_id).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command CloseTLSSession {:?}",
                    e
                ))
            })?;
        }
        RuntimeManagerOpcode::GetTLSDataNeeded => {
            debug_message("runtime_manager_trustzone::invoke_command GetTLSDataNeeded".to_string());
            let mut values = unsafe {
                params.0.as_value().map_err(|e| print_error_and_return(format!("runtime_manager_trustzone::invoke_command GetTLSDataNeeded failed to get param.0 as value {:?}",e)))?
            };
            let local_needed =
                managers::session_manager::get_data_needed(values.a()).map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command GetTLSDataNeeded {:?}",
                        e
                    ))
                })?;

            values.set_b(if local_needed { 1 } else { 0 })
        }
        RuntimeManagerOpcode::SendTLSData => {
            debug_message("runtime_manager_trustzone::invoke_command SendTLSData".to_string());
            let session_id = unsafe {
                params
                    .0
                    .as_value()
                    .map_err(|e| {
                        print_error_and_return(format!(
                            "runtime_manager_trustzone::invoke_command SendTLSData failed to get param.0 as value {:?}",
                            e
                        ))
                    })?
                    .a()
            };
            let mut input = unsafe {
                params.1.as_memref().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command SendTLSData failed to get param.1 as memref {:?}",
                        e
                    ))
                })?
            };
            let input_buffer = input.buffer();

            debug_message(
                "runtime_manager_trustzone::invoke_command SendTLSData calling session_manager::send_data".to_string(),
            );
            managers::session_manager::send_data(session_id, &input_buffer).map_err(|err| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command SendTLSData {:?}",
                    err
                ))
            })?;
        }
        RuntimeManagerOpcode::GetTLSData => {
            debug_message("runtime_manager_trustzone::invoke_command GetTLSData".to_string());
            let session_id = unsafe {
                params
                    .0
                    .as_value()
                    .map_err(|err| {
                        print_error_and_return(format!(
                            "runtime_manager_trustzone::invoke_command GetTLSDAta failed to get params.0 as value:{:?}",
                            err
                        ))
                    })?
                    .a()
            };
            let mut p1 = unsafe {
                params.1.as_memref().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command GetTLSData failed to get params.1 as memref:{:?}",
                        err
                    ))
                })?
            };
            let mut p2 = unsafe {
                params.2.as_value().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command GetTLSData failed to get params.2 as value:{:?}",
                        err
                    ))
                })?
            };
            let mut active_flag = unsafe {
                params.3.as_value().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command GetTLSData failed to get params.3 as value:{:?}",
                        err
                    ))
                })?
            };

            let (active_bool, output_data) = managers::session_manager::get_data(session_id)
                .map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command GetTLSData {:?}",
                        e
                    ))
                })?;

            p1.buffer().write(&output_data).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command GetTLSData failed to write buffer {:?}",
                    e
                ))
            })?;
            p2.set_a(output_data.len() as u32);
            active_flag.set_a(if active_bool { 1 } else { 0 });
        }
        RuntimeManagerOpcode::ResetEnclave => {
            debug_message("runtime_manager_trustzone::invoke_command::ResetEnclave".to_string());
        }
    }
    Ok(())
}

fn native_attestation(challenge: &Vec<u8>, csr: &Vec<u8>) -> Result<Vec<u8>, String> {
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
            "runtime_manager_truztone::native_attestation psa_initial_attest_load key failed with code:{:}",
            status
        ))?;
    }

    let csr_hash: Vec<u8> = digest::digest(&digest::SHA256, csr).as_ref().to_vec();

    let mut trustzone_root_enclave_hash: [u8; 32] = [0; 32];
    trustzone_root_enclave_hash.clone_from_slice(&veracruz_utils::platform::tz::TRUSTZONE_RUNTIME_MANAGER_HASH[0..32]);
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
            "runtime_manager_truztone::native_attestation psa_initial_attest_get_token failed with error code:{:}",
            status
        ));
    }
    unsafe { token_buffer.set_len(token_size as usize) };

    let status = unsafe {
        psa_initial_attest_remove_key(
            root_key_handle,
        )
    };
    if status != 0 {
        return Err(format!(
            "runtime_manager_truztone::native_attestation psa_initial_attest_remove_key failed with error code:{:?}",
            status
        ));
    }
    Ok(token_buffer.clone())
}

// TA configurations
const TA_FLAGS: u32 = optee_utee_sys::TA_FLAG_SINGLE_INSTANCE
    | optee_utee_sys::TA_FLAG_MULTI_SESSION
    | optee_utee_sys::TA_FLAG_INSTANCE_KEEP_ALIVE;
// The QEMU platform has 30MB available for the TA(code + heap + stack+ other stuff).
// The following two values leave 2MB for the code. If code grows above 2MB, these
// values will need to be changed
const TA_DATA_SIZE: u32 = 18 * 1024 * 1024;
const TA_STACK_SIZE: u32 = 1 * 1024 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"Runtime Manager TA for Veracruz\0";
const EXT_PROP_VALUE_1: &[u8] = b"Runtime Manager TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"RM\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));

// NOTE: fix a mystery where a bcmp function implementation is required for compiling the
// Runtime Manager which optee does not provide.
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
