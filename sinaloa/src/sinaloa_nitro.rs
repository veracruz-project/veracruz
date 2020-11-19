//! Nitro-Enclave-specific material for Sinaloa
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
    use veracruz_utils::{NitroRootEnclaveMessage, NitroEnclave, MCMessage, NitroStatus };
    use crate::sinaloa::SinaloaError;
    use crate::ec2_instance::EC2Instance;

    const MEXICO_CITY_EIF_PATH: &str = "../mexico-city/mexico_city.eif";
    const NITRO_ROOT_ENCLAVE_EIF_PATH: &str = "../nitro-root-enclave/nitro_root_enclave.eif";
    const NITRO_ROOT_ENCLAVE_SERVER_PATH: &str = "../nitro-root-enclave-server/target/debug/nitro-root-enclave-server";

    lazy_static! {
        //static ref NRE_CONTEXT: Mutex<Option<NitroEnclave>> = Mutex::new(None);
        static ref NRE_CONTEXT: Mutex<Option<EC2Instance>> = Mutex::new(None);
    }

    pub struct SinaloaNitro {
        enclave: NitroEnclave
    }

    impl Sinaloa for SinaloaNitro {
        fn new(policy_json: &str) -> Result<Self, SinaloaError> {
            // Set up, initialize Nitro Root Enclave
            let policy: veracruz_utils::VeracruzPolicy =
                veracruz_utils::VeracruzPolicy::from_json(policy_json)?;

            {
                let mut jc_guard = NRE_CONTEXT.lock()?;
                if jc_guard.is_none() {
                    println!("NITRO ROOT ENCLAVE IS UNINITIALIZED.");
                    let nre_context = SinaloaNitro::native_attestation(
                        &policy.tabasco_url(),
                        &policy.mexico_city_hash(),
                    )?;
                    *jc_guard = Some(nre_context);
                }
            }

            println!("SinaloaNitro::new native_attestation complete. instantiating Mexico City");
            let mexico_city_enclave = NitroEnclave::new(MEXICO_CITY_EIF_PATH, true)
                .map_err(|err| SinaloaError::NitroError(err))?;
            println!("SinaloaNitro::new NitroEnclave::new returned");
            let meta = Self {
                enclave: mexico_city_enclave,
            };
            println!("SinaloaNitro::new Mexico City instantiated. Calling initialize");
            std::thread::sleep(std::time::Duration::from_millis(10000));


            let initialize: MCMessage = MCMessage::Initialize(policy_json.to_string());

            let encoded_buffer: Vec<u8> = bincode::serialize(&initialize)?;
            meta.enclave.send_buffer(&encoded_buffer)?;

            // read the response
            let status_buffer = meta.enclave.receive_buffer()?;
            println!("SinaloaNitro::new Mexicy City initialize returned. CHecking status");

            let message: MCMessage = bincode::deserialize(&status_buffer[..])?;
            let status = match message {
                MCMessage::Status(status) => status,
                _ => return Err(SinaloaError::MCMessageStatus(message)),
            };
            match status {
                NitroStatus::Success => (),
                _ => return Err(SinaloaError::NitroStatus(status)),
            }
            println!("SinaloaNitro::new complete. Returning");
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
            tabasco_url: &str,
            mexico_city_hash: &str,
        //) -> Result<NitroEnclave, SinaloaError> {
        ) -> Result<EC2Instance, SinaloaError> {
            println!("SinaloaNitro::native_attestation started");

            println!("Starting EC2 instance");
            let nre_instance = EC2Instance::new()
                .map_err(|err| SinaloaError::EC2Error(err))?;

            nre_instance.upload_file(NITRO_ROOT_ENCLAVE_EIF_PATH, "/home/ec2-user/nitro_root_enclave.eif")
                .map_err(|err| SinaloaError::EC2Error(err))?;
            nre_instance.upload_file(NITRO_ROOT_ENCLAVE_SERVER_PATH, "/home/ec2-user/nitro-root-enclave-server")
                .map_err(|err| SinaloaError::EC2Error(err))?;

            nre_instance.execute_command("nitro-cli-config -t 2 -m 512")
                .map_err(|err| SinaloaError::EC2Error(err))?;
            let server_command: String = format!("nohup /home/ec2-user/nitro-root-enclave-server {:}", tabasco_url);
            nre_instance.execute_command(&server_command)
                .map_err(|err| SinaloaError::EC2Error(err))?;
            // let nre_instance = EC2Instance {
            //     instance_id: "i-023b3ab5f067109bd".to_string(),
            //     private_ip: "192.168.46.82:22".to_string(),
            //     socket_port: 9090,
            // };
            //nre_instance.close();
            //let nre_enclave = NitroEnclave::new(NITRO_ROOT_ENCLAVE_EIF_PATH)?;
            println!("Waiting for NRE Instance to authenticate. Now is the time for you to start it manually, Derek");
            println!("Here's your command: nitro-root-enclave-server {:?}", tabasco_url);
            std::thread::sleep(std::time::Duration::from_millis(20000));

            println!("SinaloaNitro::native_attstation new completed. fetching firmware version");
            //let firmware_version = SinaloaNitro::fetch_firmware_version(&nre_enclave)?;
            // let firmware_version = SinaloaNitro::fetch_firmware_version(&nre_instance)?;
            // println!("SinaloaNitro::native_attestation fetch_firmware_version complete. Now setting mexico city hash");

            // {
            //     let mexico_city_hash_vec =
            //         hex::decode(mexico_city_hash)?;
                
            //     let message = NitroRootEnclaveMessage::SetMexicoCityHashHack(mexico_city_hash_vec);
            //     let message_buffer = bincode::serialize(&message)?;
            //     println!("SinaloaNitro::native_attestation sending buffer:{:?}", message_buffer);
            //     //nre_enclave.send_buffer(&message_buffer)?;
            //     nre_instance.send_buffer(&message_buffer)?;

            //     //let return_buffer = nre_enclave.receive_buffer()?;
            //     let return_buffer = nre_instance.receive_buffer()?;
            //     let received_message = bincode::deserialize(&return_buffer)?;
            //     let status = match received_message {
            //         NitroRootEnclaveMessage::Status(status) => status,
            //         _ => return Err(SinaloaError::InvalidNitroRootEnclaveMessage(received_message))?,
            //     };
            //     match status {
            //         NitroStatus::Success => (),
            //         _ => return Err(SinaloaError::NitroStatus(status)),
            //     }
            // }
            // println!("SinaloaNitro::native_attestation completed setting Mexico City Hash. Now sending start to tabasco");
            // let (challenge, device_id) =
            //     SinaloaNitro::send_start(tabasco_url, "nitro", &firmware_version)?;

            // println!("SinaloaNitro::native_attestation completed send to tabasco. Now sending NativeAttestation message to Nitro Root Enclave");
            // let message = NitroRootEnclaveMessage::NativeAttestation(challenge, device_id);
            // let message_buffer = bincode::serialize(&message)?;
            // //nre_enclave.send_buffer(&message_buffer)?;
            // nre_instance.send_buffer(&message_buffer)?;

            // // data returned is token, public key
            // //let return_buffer = nre_enclave.receive_buffer()?;
            // let return_buffer = nre_instance.receive_buffer()?;
            // let received_message = bincode::deserialize(&return_buffer)?;
            // let (token, _public_key) = match received_message {
            //     NitroRootEnclaveMessage::TokenData(tok, pubkey) => (tok, pubkey),
            //     _ => return Err(SinaloaError::InvalidNitroRootEnclaveMessage(received_message)),
            // };

            // println!("SinaloaNitro::native_attestation posting native_attestation_token to tabasco");
            // SinaloaNitro::post_native_attestation_token(tabasco_url, &token, device_id)?;
            println!("sinaloa_tz::native_attestation returning Ok");
            //return Ok(nre_enclave);
            return Ok(nre_instance);
        }

        fn post_native_attestation_token(
            tabasco_url: &str,
            token: &Vec<u8>,
            device_id: i32,
        ) -> Result<(), SinaloaError> {
            println!("sinaloa_nitro::post_native_attestation_token started");
            let serialized_tabasco_request =
                colima::serialize_native_psa_attestation_token(token, device_id)?;
            let encoded_str = base64::encode(&serialized_tabasco_request);
            let url = format!("{:}/Nitro/AttestationToken", tabasco_url);
            println!("sinaloa_nitro::post_native_attestation_token posting to URL{:?}", url);
            let response = crate::post_buffer(&url, &encoded_str)?;

            println!(
                "sinaloa_tz::post_psa_attestation_token received buffer:{:?}",
                response
            );
            return Ok(());
        }

        //fn fetch_firmware_version(nre_enclave: &NitroEnclave) -> Result<String, SinaloaError> {
        fn fetch_firmware_version(nre_instance: &EC2Instance) -> Result<String, SinaloaError> {
            println!("SInaloaNitro::fetch_firmware_version started");

            let firmware_version: String = {
                let message = NitroRootEnclaveMessage::FetchFirmwareVersion;
                let message_buffer = bincode::serialize(&message)?;
                println!("SinaloaNitro::Fetch_firmware_version sending message_buffer:{:?}", message_buffer);
                //nre_enclave.send_buffer(&message_buffer)?;
                nre_instance.send_buffer(&message_buffer)?;

                //let returned_buffer = nre_enclave.receive_buffer()?;
                let returned_buffer = nre_instance.receive_buffer()?;
                let response: NitroRootEnclaveMessage = bincode::deserialize(&returned_buffer)?;
                match response {
                    NitroRootEnclaveMessage::FirmwareVersion(version) => version,
                    _ => return Err(SinaloaError::InvalidNitroRootEnclaveMessage(response)),
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
