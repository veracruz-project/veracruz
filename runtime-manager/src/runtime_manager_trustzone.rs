//! Arm TrustZone-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers;
use crate::managers::debug_message;
use libc;
#[cfg(feature = "tz")]
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session,
    ErrorKind, Parameters, Result, 
};
use std::{
    convert::TryFrom,
    io::Write,
};
use veracruz_utils::platform::tz::runtime_manager_opcode::RuntimeManagerOpcode;

fn print_error_and_return(message: String) -> ErrorKind {
    crate::managers::error_message(message, std::u32::MAX);
    ErrorKind::Unknown
}

#[ta_create]
#[cfg(feature = "tz")]
fn create() -> Result<()> {
    debug_message("runtime_manager_trustzone:create".to_string());
    Ok(())
}

#[ta_open_session]
#[cfg(feature = "tz")]
fn open_session(_params: &mut Parameters) -> Result<()> {
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
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
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

            crate::managers::session_manager::init_session_manager(&policy).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command Initialize {:?}",
                    e
                ))
            })?;
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
        RuntimeManagerOpcode::GetCSR => {
            // p0 - challenge input
            // p1 - buffer for the CSR
            debug_message(
                "runtime_manager_trustzone::invoke_command GetCSR".to_string(),
            );

            // We don't currently have anything to do with the challenge value
            // (since we are faking attestation on TrustZone platforms for now)
            let mut _challenge = unsafe {
                let mut memref = params.0.as_memref().map_err(|err|
                    print_error_and_return(format!("runtime_manager_trustzone::invoke_command::GetCSR failed to get memref from params.0:{:?}", err))
                )?;
                memref.buffer().to_vec()
            };
            let mut csr_buf = unsafe {
                params.1.as_memref().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_trustzone::invoke_command GetTLSData failed to get params.1 as memref:{:?}",
                        err
                    ))
                })?
            };

            // Generate the CSR
            // TODO: add challenge as an extension in CSR? Is that something
            // we want to do?
            let csr = managers::session_manager::generate_csr()
                .map_err(|err| print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command PopulateCertificates generate_csr failed:{:?}",
                    err
                )))?;

            csr_buf.buffer().write(&csr).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_trustzone::invoke_command GetCSR failed to write buffer {:?}",
                    e
                ))
            })?;
        }
        RuntimeManagerOpcode::PopulateCertificates => {
            // p0 - cert_chain_buffer - input
            // p1 - cert_lengths as [u8]
            debug_message("runtime_manager_trustzone::invoke_command::PopulateCertificates started".to_string());
            let cert_chain_buffer = unsafe {
                let mut memref = params.0.as_memref().map_err(|err|
                    print_error_and_return(format!("runtime_manager_trustzone::invoke_command::PopulateCertificates failed to get memref from params.0:{:?}", err))
                )?;
                memref.buffer().to_vec()
            };
            // cert_lengths should be [u32], but optee-utee doesn't support that.
            // So, we create cert_lengths_native, which is a [u8], and then
            // transmute it to [u32]
            let cert_lengths_native = unsafe {
                let mut memref = params.1.as_memref().map_err(|err|
                    print_error_and_return(format!("runtime_manager_trustzone::invoke_command::PopulateCertificates failed to get memref from params.1:{:?}", err))
                )?;
                memref.buffer().to_vec()
            };
            // Here's where we transmute the [u8] buffer into a [u32]
            let cert_lengths = veracruz_utils::platform::tz::transmute_to_u32(&cert_lengths_native);
            let certs: Vec<Vec<u8>> = crate::runtime_manager::break_up_cert_array(&cert_chain_buffer, &cert_lengths)
                .map_err(|err| print_error_and_return(format!("runtime_manager_trustzone::invoke_command::PopulateCertificates failed on call to break_up_cert_array:{:?}", err)))?;

            managers::session_manager::load_cert_chain(certs)
                .map_err(|err| print_error_and_return(format!("runtime_manager_trustzone::invoke_command::PopulateCertificates failed on call to break_up_cert_array:{:?}", err)))?;
        },
        RuntimeManagerOpcode::ResetEnclave => {
            debug_message("runtime_manager_trustzone::invoke_command::ResetEnclave".to_string());
        }
    }
    Ok(())
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
