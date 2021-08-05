//! Nitro-Enclave-specific material for the Veracruz server
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
pub mod veracruz_server_nitro {
    use crate::veracruz_server::{VeracruzServer, VeracruzServerError};
    use std::io::Read;
    use veracruz_utils::platform::nitro::nitro::{RuntimeManagerMessage, NitroStatus};
    use veracruz_utils::platform::nitro::nitro_enclave::NitroEnclave;
    use veracruz_utils::policy::policy::Policy;
    use curl::easy::{Easy, List};

    const RUNTIME_MANAGER_EIF_PATH: &str = "../runtime-manager/runtime_manager.eif";

    pub struct VeracruzServerNitro {
        enclave: NitroEnclave,
    }

    impl VeracruzServer for VeracruzServerNitro {
        fn new(policy_json: &str) -> Result<Self, VeracruzServerError> {
            // Set up, initialize Nitro Root Enclave
            let policy: Policy =
                Policy::from_json(policy_json)?;

            let (challenge, challenge_id) = send_attestation_start(policy.proxy_attestation_server_url())?;

            println!("VeracruzServerNitro::new instantiating Runtime Manager");
            #[cfg(feature = "debug")]
            let runtime_manager_enclave = {
                println!("Starting Runtime Manager enclave in debug mode");
                NitroEnclave::new(
                    false,
                    RUNTIME_MANAGER_EIF_PATH,
                    true,
                )
                .map_err(|err| VeracruzServerError::NitroError(err))?
            };
            #[cfg(not(feature = "debug"))]
            let runtime_manager_enclave = {
                println!("Starting Runtime Manager enclave in release mode");
                NitroEnclave::new(
                    false,
                    RUNTIME_MANAGER_EIF_PATH,
                    false,
                )
                .map_err(|err| VeracruzServerError::NitroError(err))?
            };
            println!("VeracruzServerNitro::new NitroEnclave::new returned");
            let meta = Self {
                enclave: runtime_manager_enclave,
            };
            println!("VeracruzServerNitro::new Runtime Manager instantiated. Calling initialize");
            std::thread::sleep(std::time::Duration::from_millis(10000));

            let attesstation_doc = {
                let attestation = RuntimeManagerMessage::Attestation(challenge, challenge_id);
                meta.enclave.send_buffer(&bincode::serialize(&attestation)?)?;
                // read the response
                let response = meta.enclave.receive_buffer()?;
                match bincode::deserialize(&response[..])? {
                    RuntimeManagerMessage::AttestationData(doc) => doc,
                    response_message => return Err(VeracruzServerError::RuntimeManagerMessageStatus(response_message)),
                }
            };

            let cert_chain = post_native_attestation_token(policy.proxy_attestation_server_url(), &attesstation_doc, challenge_id)?;

            let initialize: RuntimeManagerMessage = RuntimeManagerMessage::Initialize(policy_json.to_string(), cert_chain);

            let encoded_buffer: Vec<u8> = bincode::serialize(&initialize)?;
            meta.enclave.send_buffer(&encoded_buffer)?;

            // read the response
            let status_buffer = meta.enclave.receive_buffer()?;

            let message: RuntimeManagerMessage = bincode::deserialize(&status_buffer[..])?;
            let status = match message {
                RuntimeManagerMessage::Status(status) => status,
                _ => return Err(VeracruzServerError::RuntimeManagerMessageStatus(message)),
            };
            match status {
                NitroStatus::Success => (),
                _ => return Err(VeracruzServerError::NitroStatus(status)),
            }
            println!("VeracruzServerNitro::new complete. Returning");
            return Ok(meta);
        }

        fn plaintext_data(&self, _data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError> {
            return Err(VeracruzServerError::UnimplementedError);
        }

        fn new_tls_session(&self) -> Result<u32, VeracruzServerError> {
            let nls_message = RuntimeManagerMessage::NewTLSSession;
            let nls_buffer = bincode::serialize(&nls_message)?;
            self.enclave.send_buffer(&nls_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            let session_id = match received_message {
                RuntimeManagerMessage::TLSSession(sid) => sid,
                _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
            };
            return Ok(session_id);
        }

        fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError> {
            let cts_message = RuntimeManagerMessage::CloseTLSSession(session_id);
            let cts_buffer = bincode::serialize(&cts_message)?;

            self.enclave.send_buffer(&cts_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            return match received_message {
                RuntimeManagerMessage::Status(_status) => Ok(()),
                _ => Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
            };
        }

        fn tls_data(
            &mut self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError> {
            let std_message: RuntimeManagerMessage = RuntimeManagerMessage::SendTLSData(session_id, input);
            let std_buffer: Vec<u8> = bincode::serialize(&std_message)?;

            self.enclave.send_buffer(&std_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            match received_message {
                RuntimeManagerMessage::Status(status) => match status {
                    NitroStatus::Success => (),
                    _ => return Err(VeracruzServerError::NitroStatus(status)),
                },
                _ => return Err(VeracruzServerError::InvalidRuntimeManagerMessage(received_message)),
            }

            let mut active_flag = true;
            let mut ret_array = Vec::new();
            while self.tls_data_needed(session_id)? {
                let gtd_message = RuntimeManagerMessage::GetTLSData(session_id);
                let gtd_buffer: Vec<u8> = bincode::serialize(&gtd_message)?;

                self.enclave.send_buffer(&gtd_buffer)?;

                let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

                let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
                match received_message {
                    RuntimeManagerMessage::TLSData(data, alive) => {
                        active_flag = alive;
                        ret_array.push(data);
                    }
                    _ => return Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
                }
            }

            Ok((
                active_flag,
                if ret_array.len() > 0 {
                    Some(ret_array)
                } else {
                    None
                },
            ))
        }

        fn close(&mut self) -> Result<bool, VeracruzServerError> {
            let re_message: RuntimeManagerMessage = RuntimeManagerMessage::ResetEnclave;
            let re_buffer: Vec<u8> = bincode::serialize(&re_message)?;

            self.enclave.send_buffer(&re_buffer)?;

            return Ok(true);
        }
    }

    impl Drop for VeracruzServerNitro {
        fn drop(&mut self) {
            match self.close() {
                Err(err) => println!("VeracruzServerNitro::drop failed in call to self.close:{:?}, we will persevere, though.", err),
                _ => (),
            }
        }
    }

    impl VeracruzServerNitro {
        fn tls_data_needed(&self, session_id: u32) -> Result<bool, VeracruzServerError> {
            let gtdn_message = RuntimeManagerMessage::GetTLSDataNeeded(session_id);
            let gtdn_buffer: Vec<u8> = bincode::serialize(&gtdn_message)?;

            self.enclave.send_buffer(&gtdn_buffer)?;

            let received_buffer: Vec<u8> = self.enclave.receive_buffer()?;

            let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)?;
            let tls_data_needed = match received_message {
                RuntimeManagerMessage::TLSDataNeeded(needed) => needed,
                _ => return Err(VeracruzServerError::NitroStatus(NitroStatus::Fail)),
            };
            return Ok(tls_data_needed);
        }
    }

    /// Send the native (AWS Nitro) attestation token to the proxy attestation server
    fn post_native_attestation_token(
        proxy_attestation_server_url: &str,
        att_doc: &[u8],
        challenge_id: i32,
    ) -> Result<Vec<Vec<u8>>, VeracruzServerError> {
        let serialized_nitro_attestation_doc_request =
            transport_protocol::serialize_nitro_attestation_doc(att_doc, challenge_id)
                .map_err(|err| VeracruzServerError::TransportProtocol(err))?;
        let encoded_str = base64::encode(&serialized_nitro_attestation_doc_request);
        let url = format!("{:}/Nitro/AttestationToken", proxy_attestation_server_url);
        println!(
            "veracruz-server-nitro::post_native_attestation_token posting to URL{:?}",
            url
        );
        let received_body: String = post_buffer(&url, &encoded_str)?;

        println!(
            "veracruz-server-nitro::post_psa_attestation_token received buffer:{:?}",
            received_body
        );

        let body_vec =
            base64::decode(&received_body).map_err(|err| VeracruzServerError::Base64Decode(err))?;
        let response =
            transport_protocol::parse_proxy_attestation_server_response(&body_vec).map_err(|err| VeracruzServerError::TransportProtocol(err))?;

        let (re_cert, ca_cert) = if response.has_cert_chain() {
            let cert_chain = response.get_cert_chain();
            (cert_chain.get_enclave_cert(), cert_chain.get_root_cert())
        } else {
            return Err(VeracruzServerError::InvalidProtoBufMessage);
        };
        let mut cert_chain: Vec<Vec<u8>> = Vec::new();
        cert_chain.push(re_cert.to_vec());
        cert_chain.push(ca_cert.to_vec());
        return Ok(cert_chain);
    }

    /// Send the start message to the proxy attestation server (this triggers the server to
    /// send the challenge) and then handle the response
    fn send_attestation_start(
        url_base: &str,
    ) -> Result<(Vec<u8>, i32), VeracruzServerError> {
        let proxy_attestation_server_response = send_proxy_attestation_server_start(url_base)?;
        if proxy_attestation_server_response.has_psa_attestation_init() {
            let (challenge, device_id) =
                transport_protocol::parse_psa_attestation_init(proxy_attestation_server_response.get_psa_attestation_init())
                    .map_err(|err| VeracruzServerError::TransportProtocol(err))?;
            return Ok((challenge, device_id));
        } else {
            return Err(VeracruzServerError::InvalidProtoBufMessage);
        }
    }

    /// Send start to the proxy attestation server.
    fn send_proxy_attestation_server_start(
        url_base: &str,
    ) -> Result<transport_protocol::ProxyAttestationServerResponse, VeracruzServerError> {
        let serialized_start_msg = transport_protocol::serialize_start_msg("nitro", "0.0")
            .map_err(|err| VeracruzServerError::TransportProtocol(err))?;
        let encoded_start_msg: String = base64::encode(&serialized_start_msg);
        let url = format!("{:}/Start", url_base);

        println!(
            "nitro-root-enclave-server::send_proxy_attestation_server_start sending to url:{:?}",
            url
        );
        let received_body: String = post_buffer(&url, &encoded_start_msg)?;
        println!("nitro-root-enclave-server::send_proxy_attestation_server_start completed post command");

        let body_vec =
            base64::decode(&received_body).map_err(|err| VeracruzServerError::Base64Decode(err))?;
        let response =
            transport_protocol::parse_proxy_attestation_server_response(&body_vec).map_err(|err| VeracruzServerError::TransportProtocol(err))?;
        println!("nitro-root-enclave-server::send_proxy_attestation_server_start completed. Returning.");
        return Ok(response);
    }

    /// Post a buffer to a remote HTTP server
    fn post_buffer(url: &str, buffer: &String) -> Result<String, VeracruzServerError> {
        let mut buffer_reader = stringreader::StringReader::new(buffer);

        let mut curl_request = Easy::new();
        curl_request
            .url(&url)
            .map_err(|err| VeracruzServerError::CurlError(err))?;
        let mut headers = List::new();
        headers
            .append("Content-Type: application/octet-stream")
            .map_err(|err| VeracruzServerError::CurlError(err))?;
        curl_request
            .http_headers(headers)
            .map_err(|err| VeracruzServerError::CurlError(err))?;
        curl_request
            .post(true)
            .map_err(|err| VeracruzServerError::CurlError(err))?;
        curl_request
            .post_field_size(buffer.len() as u64)
            .map_err(|err| VeracruzServerError::CurlError(err))?;

        let mut received_body = String::new();
        let mut received_header = String::new();
        {
            let mut transfer = curl_request.transfer();

            transfer
                .read_function(|buf| Ok(buffer_reader.read(buf).unwrap_or(0)))
                .map_err(|err| VeracruzServerError::CurlError(err))?;
            transfer
                .write_function(|buf| {
                    received_body.push_str(
                        std::str::from_utf8(buf)
                            .expect(&format!("Error converting data {:?} from UTF-8", buf)),
                    );
                    Ok(buf.len())
                })
                .map_err(|err| VeracruzServerError::CurlError(err))?;

            transfer
                .header_function(|buf| {
                    received_header.push_str(
                        std::str::from_utf8(buf)
                            .expect(&format!("Error converting data {:?} from UTF-8", buf)),
                    );
                    true
                })
                .map_err(|err| VeracruzServerError::CurlError(err))?;

            transfer
                .perform()
                .map_err(|err| VeracruzServerError::CurlError(err))?;
        }
        let header_lines: Vec<&str> = received_header.split("\n").collect();

        println!(
            "nitro-root-enclave-server::post_buffer received header:{:?}",
            received_header
        );
        if !received_header.contains("HTTP/1.1 200 OK\r") {
            return Err(VeracruzServerError::NonSuccessHttp);
        }

        println!(
            "nitro-root-enclave-server::post_buffer header_lines:{:?}",
            header_lines
        );

        return Ok(received_body);
    }
}
