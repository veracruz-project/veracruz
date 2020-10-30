//! Arm Nitro-Enclave-specific material for Sinaloa
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "nitro")]
pub mod sinaloa_nitro {
    use crate::sinaloa::Sinaloa;
    use hex;
    use lazy_static::lazy_static;
    use std::sync::Mutex;
    use veracruz_utils::{ChiapasMessage, MCMessage, NitroStatus };
    use crate::nitro_enclave::NitroEnclave;
    use crate::sinaloa::SinaloaError;

    const MEXICO_CITY_EIF_PATH: &str = "../mexico-city/mexico_city.eif";
    const CHIAPAS_EIF_PATH: &str = "../chiapas/chiapas.eif";

    lazy_static! {
        static ref CHIAPAS_CONTEXT: Mutex<Option<NitroEnclave>> = Mutex::new(None);
    }

    pub struct SinaloaNitro {
        enclave: NitroEnclave
    }

    impl Sinaloa for SinaloaNitro {
        fn new(policy_json: &str) -> Result<Self, SinaloaError> {
            // Set up, initialize Chiapas
            let policy: veracruz_utils::VeracruzPolicy =
                veracruz_utils::VeracruzPolicy::from_json(policy_json)?;

            {
                let mut jc_guard = CHIAPAS_CONTEXT.lock()?;
                if jc_guard.is_none() {
                    println!("CHIAPAS IS UNINITIALIZED.");
                    let chiapas_context = SinaloaNitro::native_attestation(
                        &policy.tabasco_url(),
                        &policy.mexico_city_hash(),
                    )?;
                    *jc_guard = Some(chiapas_context);
                }
            }

            let mexico_city_enclave = NitroEnclave::new(MEXICO_CITY_EIF_PATH)?;
            let meta = Self {
                enclave: mexico_city_enclave,
            };

            let initialize: MCMessage = MCMessage::Initialize(policy_json.to_string());

            let encoded_buffer: Vec<u8> = bincode::serialize(&initialize)?;
            meta.enclave.send_buffer(&encoded_buffer)?;

            // read the response
            let status_buffer = meta.enclave.receive_buffer()?;

            let message: MCMessage = bincode::deserialize(&status_buffer[..])?;
            let status = match message {
                MCMessage::Status(status) => status,
                _ => return Err(SinaloaError::MCMessageStatus(message)),
            };
            match status {
                NitroStatus::Success => (),
                _ => return Err(SinaloaError::NitroStatus(status)),
            }

            return Ok(meta);
        }

        fn plaintext_data(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>, SinaloaError> {
            let parsed = colima::parse_mexico_city_request(&data)?;

            if parsed.has_request_proxy_psa_attestation_token() {
                let rpat = parsed.get_request_proxy_psa_attestation_token();
                let challenge = colima::parse_request_proxy_psa_attestation_token(rpat);
                let (psa_attestation_token, pubkey, device_id) =
                    self.proxy_psa_attestation_get_token(challenge)?;
                let serialized_pat = colima::serialize_proxy_psa_attestation_token(
                    &psa_attestation_token,
                    &pubkey,
                    device_id,
                )?;
                Ok(Some(serialized_pat))
            } else {
                unreachable!("Unimplemented");
            }
        }

        // Note: this function will go away
        fn get_enclave_cert(&self) -> Result<Vec<u8>, SinaloaError> {

            let certificate = {
                let message = MCMessage::GetEnclaveCert;
                let message_buffer = bincode::serialize(&message)?;
                self.enclave.send_buffer(&message_buffer)?;
                // Read the resulting data as the certificate
                let received_buffer = self.enclave.receive_buffer()?;
                let received_message: MCMessage = bincode::deserialize(&received_buffer)?;
                match received_message {
                    MCMessage::EnclaveCert(cert) => cert,
                    _ => return Err(SinaloaError::InvalidMCMessage(received_message))?,
                }
            };
            Ok(certificate)
        }

        // Note: This function will go away
        fn get_enclave_name(&self) -> Result<String, SinaloaError> {
           
            let name: String = {
                let message = MCMessage::GetEnclaveName;
                let message_buffer = bincode::serialize(&message)?;
                self.enclave.send_buffer(&message_buffer)?;
                // Read the resulting data as the name
                let received_buffer = self.enclave.receive_buffer()?;
                let received_message: MCMessage = bincode::deserialize(&received_buffer)?;
                match received_message {
                    MCMessage::EnclaveName(name) => name,
                    _ => return Err(SinaloaError::InvalidMCMessage(received_message)),
                }
            };
            Ok(name)
        }

        fn proxy_psa_attestation_get_token(
            &self,
            challenge: Vec<u8>,
        ) -> Result<(Vec<u8>, Vec<u8>, i32), SinaloaError> {
            let message = MCMessage::GetPSAAttestationToken(challenge);
            let message_buffer = bincode::serialize(&message)?;
            self.enclave.send_buffer(&message_buffer)?;
            
            let mut received_buffer = self.enclave.receive_buffer()?;
            let received_message: MCMessage = bincode::deserialize(&received_buffer)?;
            let (token, public_key, device_id) = match received_message {
                MCMessage::PSAAttestationToken(token, public_key, device_id) => (token, public_key, device_id),
                _ => return Err(SinaloaError::InvalidMCMessage(received_message)),
            };
            Ok((token, public_key, device_id))
        }

        fn new_tls_session(&self) -> Result<u32, SinaloaError> {
            let protobuf: Vec<u8> = Vec::new();
            // TODO: fill protobuf with NewTLSSession
            self.enclave.send_buffer(&protobuf)?;
            
            let return_buffer = self.enclave.receive_buffer()?;
            // TODO: Parse return buffer, extract session_id
            let session_id: u32 = 0;

            Ok(session_id)
        }

        fn close_tls_session(&self, session_id: u32) -> Result<(), SinaloaError> {
            let protobuf: Vec<u8> = Vec::new();
            // TODO: Fill protobuf with CloseTLSSession, session_id

            self.enclave.send_buffer(&protobuf)?;

            let return_buffer = self.enclave.receive_buffer()?;
            // TODO: parse return_buffer, check status

            Ok(())
        }

        fn tls_data(
            &self,
            session_id: u32,
            input: Vec<u8>,
        ) -> Result<(bool, Option<Vec<Vec<u8>>>), SinaloaError> {
            let protobuf: Vec<u8> = Vec::new();
            // TODO: Fill protobuf with SendTLSData, input_data
            self.enclave.send_buffer(&protobuf)?;

            let return_buffer = self.enclave.receive_buffer()?;
            // TODO: parse return_buffer, check status

            let active_flag = true;
            let mut ret_array = Vec::new();
            while self.tls_data_needed(session_id)? {
                let protobuf: Vec<u8> = Vec::new();
                // TODO: Fill protobuf with GetTLSData, session_id, active_flag
                self.enclave.send_buffer(&protobuf)?;

                let return_buffer = self.enclave.receive_buffer()?;
                // TODO parse return_buffer into active_flag, output_data
                // TODO: update active_flag with new value
                let output_data: Vec<u8> = Vec::new();
                ret_array.push(output_data.to_vec());
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

        fn close(&mut self) -> Result<bool, SinaloaError> {
            let protobuf: Vec<u8> = Vec::new();
            // TODO: fill protobuf with  ResetEnclave
            self.enclave.send_buffer(&protobuf)?;

            let return_buffer = self.enclave.receive_buffer()?;
            // TODO: Parse return status, do something with it
            Ok(true)
        }
    }

    impl Drop for SinaloaNitro {
        fn drop(&mut self) {
            match self.close() {
                Err(err) => println!("SinaloaNitro::drop failed in call to self.close:{:?}", err),
                _ => (),
            }
        }
    }

    impl SinaloaNitro {
        fn tls_data_needed(&self, session_id: u32) -> Result<bool, SinaloaError> {
            let protobuf: Vec<u8> = Vec::new();
            // TODO: fill protobuf with GetTLSDataNeeded, session_id

            self.enclave.send_buffer(&protobuf)?;

            let return_buffer = self.enclave.receive_buffer()?;
            // TODO: parse result as true/false
            // set data_needed to result
            let data_needed = true;
            Ok(data_needed)
        }

        fn native_attestation(
            tabasco_url: &String,
            mexico_city_hash: &String,
        ) -> Result<NitroEnclave, SinaloaError> {
            println!("SinaloaNitro::native_attestation started");
            let chiapas_enclave = NitroEnclave::new(CHIAPAS_EIF_PATH)?;

            println!("SinaloaNitro::native_attstation new completed. fetching firmware version");
            let firmware_version = SinaloaNitro::fetch_firmware_version(&chiapas_enclave)?;
            println!("SinaloaNitro::native_attestation fetch_firmware_version complete. Now setting mexico city hash");

            {
                let mexico_city_hash_vec =
                    hex::decode(mexico_city_hash.as_str())?;
                
                let message = ChiapasMessage::SetMexicoCityHashHack(mexico_city_hash_vec);
                let message_buffer = bincode::serialize(&message)?;
                println!("SinaloaNitro::native_attestation sending buffer:{:?}", message_buffer);
                chiapas_enclave.send_buffer(&message_buffer)?;

                let return_buffer = chiapas_enclave.receive_buffer()?;
                let received_message = bincode::deserialize(&return_buffer)?;
                let status = match received_message {
                    ChiapasMessage::Status(status) => status,
                    _ => return Err(SinaloaError::InvalidChiapasMessage(received_message))?,
                };
                match status {
                    NitroStatus::Success => (),
                    _ => return Err(SinaloaError::NitroStatus(status)),
                }
            }
            println!("SinaloaNitro::native_attestation completed setting Mexico City Hash. Now sending start to tabasco");
            let (challenge, device_id) =
                SinaloaNitro::send_start(tabasco_url, "psa", &firmware_version)?;

            println!("SinaloaNitro::native_attestation completed send to tabasco. Now sending NativeAttestation message to chiapas");
            let message = ChiapasMessage::NativeAttestation(challenge, device_id);
            let message_buffer = bincode::serialize(&message)?;
            chiapas_enclave.send_buffer(&message_buffer)?;

            // data returned is token, public key
            let return_buffer = chiapas_enclave.receive_buffer()?;
            let received_message = bincode::deserialize(&return_buffer)?;
            let (token, public_key) = match received_message {
                ChiapasMessage::TokenData(tok, pubkey) => (tok, pubkey),
                _ => return Err(SinaloaError::InvalidChiapasMessage(received_message)),
            };

            println!("SinaloaNitro::native_attestation posting native_psa_attestation_token to tabasco");
            SinaloaNitro::post_native_psa_attestation_token(tabasco_url, &token, device_id)?;
            println!("sinaloa_tz::native_attestation returning Ok");
            return Ok(chiapas_enclave);
        }

        fn post_native_psa_attestation_token(
            tabasco_url: &String,
            token: &Vec<u8>,
            device_id: i32,
        ) -> Result<(), SinaloaError> {
            println!("sinaloa_tz::post_psa_attestation_token started");
            let serialized_tabasco_request =
                colima::serialize_native_psa_attestation_token(token, device_id)?;
            let encoded_str = base64::encode(&serialized_tabasco_request);
            let url = format!("{:}/PSA/AttestationToken", tabasco_url);
            let response = crate::post_buffer(&url, &encoded_str)?;

            println!(
                "sinaloa_tz::post_psa_attestation_token received buffer:{:?}",
                response
            );
            return Ok(());
        }

        fn fetch_firmware_version(chiapas_enclave: &NitroEnclave) -> Result<String, SinaloaError> {
            println!("SInaloaNitro::fetch_firmware_version started");

            let firmware_version: String = {
                let message = ChiapasMessage::FetchFirmwareVersion;
                let message_buffer = bincode::serialize(&message)?;
                println!("SinaloaNitro::Fetch_firmware_version sending message_buffer:{:?}", message_buffer);
                chiapas_enclave.send_buffer(&message_buffer)?;

                let returned_buffer = chiapas_enclave.receive_buffer()?;
                let response: ChiapasMessage = bincode::deserialize(&returned_buffer)?;
                match response {
                    ChiapasMessage::FirmwareVersion(version) => version,
                    _ => return Err(SinaloaError::InvalidChiapasMessage(response)),
                }
            };
            println!("SinaloaNitro::fetch_firmware_version finished");
            return Ok(firmware_version);
        }

        fn send_start(
            url_base: &str,
            protocol: &str,
            firmware_version: &str,
        ) -> Result<(Vec<u8>, i32), SinaloaError> {
            let tabasco_response = crate::send_tabasco_start(url_base, protocol, firmware_version)?;
            match tabasco_response.has_psa_attestation_init() {
                false => {
                    return Err(SinaloaError::InvalidProtoBufMessage);
                }
                true => {
                    let (challenge, device_id) = colima::parse_psa_attestation_init(
                        tabasco_response.get_psa_attestation_init(),
                    )?;
                    return Ok((challenge, device_id));
                }
            }
        }
    }
}
