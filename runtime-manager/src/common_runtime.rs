use anyhow::Result;

use veracruz_utils::{
    runtime_manager_message::{ RuntimeManagerRequest, RuntimeManagerResponse, Status},
};

use crate::platform_runtime::PlatformRuntime;
use crate::managers;

pub struct CommonRuntime<'a> {
    platform_runtime: &'a (dyn PlatformRuntime + 'a),
}
 
impl<'a> CommonRuntime<'a> {
    pub fn new(pr: &'a dyn PlatformRuntime) -> CommonRuntime {
        return CommonRuntime {
            platform_runtime: pr,
        };
    }

    pub fn decode_dispatch(&self, received_buffer: &Vec<u8>) -> Result<Vec<u8>> {
        let received_message: RuntimeManagerRequest = bincode::deserialize(&received_buffer)?;
        let return_message = match received_message {
            RuntimeManagerRequest::Attestation(challenge, _challenge_id) => {
                self.platform_runtime.attestation(&challenge)?
            }
            RuntimeManagerRequest::Initialize(policy_json, certificate_chain) => {
                initialize(&policy_json, &certificate_chain)?
            }
            RuntimeManagerRequest::NewTlsSession => {
                let ns_result = managers::session_manager::new_session();
                let return_message: RuntimeManagerResponse = match ns_result {
                    Ok(session_id) => RuntimeManagerResponse::TlsSession(session_id),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
            RuntimeManagerRequest::CloseTlsSession(session_id) => {
                let cs_result = managers::session_manager::close_session(session_id);
                let return_message: RuntimeManagerResponse = match cs_result {
                    Ok(_) => RuntimeManagerResponse::Status(Status::Success),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
            RuntimeManagerRequest::SendTlsData(session_id, tls_data) => {
                println!("runtime_manager_nitro::main SendTlsData");
                let return_message =
                    match managers::session_manager::send_data(session_id, &tls_data) {
                        Ok(_) => RuntimeManagerResponse::Status(Status::Success),
                        Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    };
                return_message
            }
            RuntimeManagerRequest::GetTlsData(session_id) => {
                println!("runtime_manager_nitro::main GetTlsData");
                let return_message = match managers::session_manager::get_data(session_id) {
                    Ok((active, output_data)) => {
                        RuntimeManagerResponse::TlsData(output_data, active)
                    }
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
        };
        let return_buffer = bincode::serialize(&return_message)?;
        println!(
            "runtime_manager_nitro::main calling send buffer with buffer_len:{:?}",
            return_buffer.len()
        );
        return Ok(return_buffer);
    }
}

/// Handler for the RuntimeManagerRequest::Initialize message
fn initialize(policy_json: &str, cert_chain: &Vec<u8>) -> Result<RuntimeManagerResponse> {
    managers::session_manager::load_policy(policy_json)?;
    managers::session_manager::load_cert_chain(cert_chain)?;

    return Ok(RuntimeManagerResponse::Status(Status::Success));
}
