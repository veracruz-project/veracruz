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
    DifferentParameter, DifferentParameters, ErrorKind, ParamType, Parameters, Result, Session,
};
use std::{convert::TryInto, io::Write};
use veracruz_utils::RuntimeManagerOpcode;

fn print_error_and_return(message: String) -> ErrorKind {
    crate::managers::error_message(message, std::u32::MAX);
    ErrorKind::Unknown
}

#[ta_create]
#[cfg(feature = "tz")]
fn create() -> Result<()> {
    debug_message("runtime_manager_tz:create".to_string());
    Ok(())
}

#[ta_open_session]
#[cfg(feature = "tz")]
fn open_session(_params: &mut Parameters) -> Result<()> {
    debug_message("runtime_manager_tz:Open_session".to_string());
    Ok(())
}

#[ta_close_session]
#[cfg(feature = "tz")]
fn close_session() {
    debug_message("runtime_manager_tz:Close Session".to_string());
}

#[ta_destroy]
#[cfg(feature = "tz")]
fn destroy() {
    debug_message("runtime_manager_tz:destroy".to_string());
}

#[ta_invoke_command]
#[cfg(feature = "tz")]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    debug_message("runtime_manager_tz:invoke_command".to_string());
    let cmd = RuntimeManagerOpcode::from_u32(cmd_id).map_err(|err| {
        print_error_and_return(format!(
            "runtime_manager_tz::invoke_command Failed to convert opcode:{:?} to RuntimeManagerOpcode:{:?}",
            cmd_id, err
        ))
    })?;
    match cmd {
        RuntimeManagerOpcode::Initialize => {
            debug_message("runtime_manager_tz::invoke_command Initialize".to_string());
            let mut input = unsafe {
                params.0.as_memref().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command Initialize failed to get param.0 as memref {:?}",
                        e
                    ))
                })?
            };
            let input_buffer = input.buffer();
            let input_str = std::str::from_utf8(input_buffer).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_tz::invoke_command Initialize failed to convert from utf8 {:?}",
                    e
                ))
            })?;
            crate::managers::session_manager::init_session_manager(&input_str).map_err(|e| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command Initialize {:?}", e))
            })?;
        }
        RuntimeManagerOpcode::GetEnclaveCertSize => {
            debug_message("runtime_manager_tz::invoke_command GetEnclaveCertSize".to_string());
            let mut values = unsafe {
                params.0.as_value().map_err(|e| print_error_and_return(format!("runtime_manager_tz::invoke_command GetEnclaveCertSize failed to get param.0 as value {:?}",e)))?
            };
            let cert = managers::session_manager::get_enclave_cert_pem().map_err(|e| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command GetEnclaveCertSize {:?}", e))
            })?;
            values.set_a(cert.len() as u32);
        }
        RuntimeManagerOpcode::GetEnclaveCert => {
            debug_message("runtime_manager_tz::invoke_command GetEnclaveCert".to_string());
            let mut p0 = unsafe {
                params.0.as_memref().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command GetEnclaveCert failed to get param.0 as memref {:?}",
                        e
                    ))
                })?
            };
            let cert = managers::session_manager::get_enclave_cert_pem().map_err(|e| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command GetEnclaveCert {:?}", e))
            })?;
            p0.buffer().write(&cert).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_tz::invoke_command GetEnclaveCert failed to write buffer {:?}",
                    e
                ))
            })?;
        }
        RuntimeManagerOpcode::GetEnclaveNameSize => {
            debug_message("runtime_manager_tz::invoke_command GetEnclaveNameSize".to_string());
            let mut values = unsafe {
                params.0.as_value().map_err(|e| print_error_and_return(format!("runtime_manager_tz::invoke_command GetEnclaveNameSize failed to get param.0 as value {:?}",e)))?
            };
            let name = managers::session_manager::get_enclave_name().map_err(|e| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command GetEnclaveNameSize {:?}", e))
            })?;
            values.set_a(name.len() as u32);
        }
        RuntimeManagerOpcode::GetEnclaveName => {
            debug_message("runtime_manager_tz::invoke_command GetEnclaveName".to_string());
            let mut p0 = unsafe {
                params.0.as_memref().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command GetEnclaveName failed to get param.0 as memref {:?}",
                        e
                    ))
                })?
            };
            let name = managers::session_manager::get_enclave_name().map_err(|e| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command GetEnclaveName {:?}", e))
            })?;
            p0.buffer().write(&name.as_bytes()).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_tz::invoke_command GetEnclaveName failed to write buffer {:?}",
                    e
                ))
            })?;
        }
        RuntimeManagerOpcode::NewTLSSession => {
            debug_message("runtime_manager_tz::invoke_command NewTLSSession".to_string());
            let mut values = unsafe {
                params.0.as_value().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command NewTLSSession failed to get param.0 as value {:?}",
                        e
                    ))
                })?
            };
            let local_session_id = managers::session_manager::new_session().map_err(|e| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command NewTLSSession {:?}", e))
            })?;
            values.set_a(local_session_id);
        }
        RuntimeManagerOpcode::CloseTLSSession => {
            debug_message("runtime_manager_tz::invoke_command CloseTLSSession".to_string());
            let values = unsafe {
                params.0.as_value().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command CloseTLSSession failed to get param.0 as value {:?}",
                        e
                    ))
                })?
            };
            let session_id = values.a();
            managers::session_manager::close_session(session_id).map_err(|e| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command CloseTLSSession {:?}", e))
            })?;
        }
        RuntimeManagerOpcode::GetTLSDataNeeded => {
            debug_message("runtime_manager_tz::invoke_command GetTLSDataNeeded".to_string());
            let mut values = unsafe {
                params.0.as_value().map_err(|e| print_error_and_return(format!("runtime_manager_tz::invoke_command GetTLSDataNeeded failed to get param.0 as value {:?}",e)))?
            };
            let local_needed =
                managers::session_manager::get_data_needed(values.a()).map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command GetTLSDataNeeded {:?}",
                        e
                    ))
                })?;

            values.set_b(if local_needed { 1 } else { 0 })
        }
        RuntimeManagerOpcode::SendTLSData => {
            debug_message("runtime_manager_tz::invoke_command SendTLSData".to_string());
            let session_id = unsafe {
                params
                    .0
                    .as_value()
                    .map_err(|e| {
                        print_error_and_return(format!(
                            "runtime_manager_tz::invoke_command SendTLSData failed to get param.0 as value {:?}",
                            e
                        ))
                    })?
                    .a()
            };
            let mut input = unsafe {
                params.1.as_memref().map_err(|e| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command SendTLSData failed to get param.1 as memref {:?}",
                        e
                    ))
                })?
            };
            let input_buffer = input.buffer();

            debug_message(
                "runtime_manager_tz::invoke_command SendTLSData calling session_manager::send_data".to_string(),
            );
            managers::session_manager::send_data(session_id, &input_buffer).map_err(|err| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command SendTLSData {:?}", err))
            })?;
        }
        RuntimeManagerOpcode::GetTLSData => {
            debug_message("runtime_manager_tz::invoke_command GetTLSData".to_string());
            let session_id = unsafe {
                params
                    .0
                    .as_value()
                    .map_err(|err| {
                        print_error_and_return(format!(
                            "runtime_manager_tz::invoke_command GetTLSDAta failed to get params.0 as value:{:?}",
                            err
                        ))
                    })?
                    .a()
            };
            let mut p1 = unsafe {
                params.1.as_memref().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command GetTLSData failed to get params.1 as memref:{:?}",
                        err
                    ))
                })?
            };
            let mut p2 = unsafe {
                params.2.as_value().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command GetTLSData failed to get params.2 as value:{:?}",
                        err
                    ))
                })?
            };
            let mut active_flag = unsafe {
                params.3.as_value().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command GetTLSData failed to get params.3 as value:{:?}",
                        err
                    ))
                })?
            };

            let (active_bool, output_data) =
                managers::session_manager::get_data(session_id).map_err(|e| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetTLSData {:?}", e))
                })?;

            p1.buffer().write(&output_data).map_err(|e| {
                print_error_and_return(format!(
                    "runtime_manager_tz::invoke_command GetTLSData failed to write buffer {:?}",
                    e
                ))
            })?;
            p2.set_a(output_data.len() as u32);
            active_flag.set_a(if active_bool { 1 } else { 0 });
        }
        RuntimeManagerOpcode::GetPSAAttestationToken => {
            // p0 - challenge input
            // p1 - device_id output
            // p2 - token output
            // p3 - pubkey output
            debug_message("runtime_manager_tz::invoke_command GetPSAAttestationToken".to_string());

            let mut challenge = unsafe {
                let mut memref = params.0.as_memref().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command::GetPSAAttestationToken failed to get memref from params.0:{:?}", err))
                })?;
                memref.buffer().to_vec()
            };
            let mut token_buffer = unsafe {
                let mut memref = params.2.as_memref().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command::GetPSAAttestationToken failed to get params.2 as memref:{:?}", err))
                })?;
                memref.buffer().to_vec()
            };

            let mut enclave_cert =
                managers::session_manager::get_enclave_cert_pem().map_err(|err| {
                    print_error_and_return(format!(
                        "runtime_manager_tz::invoke_command::GetPSAAttestationToken {:?}",
                        err
                    ))
                })?;

            // Need to construct a parameter list for SgxRootEnclave::ProxyAttestation
            // p0 - challenge input
            // p1 - enclave_cert input / SGXRootEnclave Pubkey Output
            // p2 - token output
            // p3 - a: device_id output b:none
            let mut sgx_root_enclave_parameters = {
                let p0 = DifferentParameter::from_vec(&mut challenge, ParamType::MemrefInput).map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command::GetPSAAttestationToken failed to create Parameter from challenge:{:?}", err))
                })?;
                let p1 = DifferentParameter::from_vec(&mut enclave_cert, ParamType::MemrefInout).map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command::GetPSAAttestationToken failed to create Parameter from enclave_cert:{:?}", err))
                })?;
                let p2 = DifferentParameter::from_vec(&mut token_buffer, ParamType::MemrefOutput).map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command::GetPSAAttestationToken failed to create parameter from token_buffer:{:?}", err))
                })?;
                let p3 = DifferentParameter::from_values(0, 0, ParamType::ValueOutput);
                DifferentParameters(p0, p1, p2, p3)
            };
            let mut session = Session::new(
                0x75bb9a28,
                0x95f8,
                0x11ea,
                [0xbb, 0x37, 0x02, 0x42, 0xac, 0x13, 0x00, 0x02],
            )?;
            session.invoke_command(3, &mut sgx_root_enclave_parameters)?;

            let token = unsafe {
                let mut memref = sgx_root_enclave_parameters.2.as_memref().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to get sgx_root_enclave_parameters.2 as memref:{:?}", err))
                })?;
                memref.buffer().to_vec()
            };
            let device_id = unsafe {
                sgx_root_enclave_parameters.3.as_value().map_err(|err| {
                print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to get sgx_root_enclave_parameters.3 as value:{:?}", err))
            })?.a()
            };
            let pubkey = unsafe {
                let mut memref = sgx_root_enclave_parameters.1.as_memref().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to get sgx_root_enclave_parameters.1 as memref:{:?}", err))
                })?;
                memref.buffer().to_vec()
            };
            unsafe {
                let mut memref = params.2.as_memref().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command::GetPSAAttestationToken failed to get params.2 as memref:{:?}", err))
                })?;
                memref.buffer().write(&token).map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to place token in token_buffer:{:?}", err))
                })?;
                (*memref.raw()).size = token.len().try_into().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to convert len into u32:{:?}", err))
                })?;
            };
            unsafe {
                params.1.as_value().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to get params.1 as value:{:?}", err))
                })?.set_a(device_id);
            }
            unsafe {
                let mut memref = params.3.as_memref().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command::GetPSAAttestationToken failed to get params.3 as memref:{:?}", err))
                })?;
                memref.buffer().write(&pubkey).map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to place pubkey in params.3:{:?}", err))
                })?;
                (*memref.raw()).size = pubkey.len().try_into().map_err(|err| {
                    print_error_and_return(format!("runtime_manager_tz::invoke_command GetPSAAttestationToken failed to convert len into u32:{:?}", err))
                })?;
            }
        }
        RuntimeManagerOpcode::ResetEnclave => {
            debug_message("runtime_manager_tz::invoke_command::ResetEnclave".to_string());
            //TODO: Check if this is necessary.
            //      If so, implmenent as the follows:
            //      let mut cs_guard = CHIHUAHUA_STATE.lock().unwrap();
            //      *cs_guard = Some(ChihuahuaState::new())
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
const TRACE_EXT_PREFIX: &[u8] = b"MC\0";
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
