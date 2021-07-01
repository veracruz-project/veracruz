//! AWS Nitro-Enclaves-specific material for the Root Enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use lazy_static::lazy_static;
use nitro_enclave_token::{AttestationDocument, NitroToken};
use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, SockAddr};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use ring::{rand::{SecureRandom, SystemRandom},signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING}};
use std::{collections::HashMap, sync::{atomic::AtomicI32, atomic::Ordering, Mutex}};
use veracruz_utils::platform::nitro::nitro::{NitroRootEnclaveMessage, NitroStatus};

use veracruz_utils::io::raw_fd::{receive_buffer, send_buffer};

use veracruz_utils::csr;

use nsm_io;
use nsm_lib;

/// The CID to be listened to for messages from the non-secure world
const CID: u32 = 0xFFFFFFFF; /// VMADDR_CID_ANY
/// The Port to listen to for messages from the non-secure world
const PORT: u32 = 5005;
/// Maximum number of outstanding connections in the socket's
/// listen queue
const BACKLOG: usize = 128;

/// The DER-encoded root certificate used to authenticate the certificate chain
/// (which is used to authenticate the Nitro Enclave tokens).
/// AWS claims that this certificate should never change (read: only change if
/// they have an extremely serious security issue), and it's expiry is set to
/// some time in 2049.
static AWS_NITRO_ROOT_CERTIFICATE: [u8; 533] = [
    0x30, 0x82, 0x02, 0x11, 0x30, 0x82, 0x01, 0x96, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x00,
    0xf9, 0x31, 0x75, 0x68, 0x1b, 0x90, 0xaf, 0xe1, 0x1d, 0x46, 0xcc, 0xb4, 0xe4, 0xe7, 0xf8, 0x56,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x49, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x03, 0x41, 0x57, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x12, 0x61, 0x77, 0x73, 0x2e, 0x6e, 0x69, 0x74, 0x72, 0x6f, 0x2d, 0x65,
    0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x73, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x32,
    0x38, 0x31, 0x33, 0x32, 0x38, 0x30, 0x35, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x30, 0x32, 0x38,
    0x31, 0x34, 0x32, 0x38, 0x30, 0x35, 0x5a, 0x30, 0x49, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x06, 0x41, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x0c, 0x03, 0x41, 0x57, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
    0x61, 0x77, 0x73, 0x2e, 0x6e, 0x69, 0x74, 0x72, 0x6f, 0x2d, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76,
    0x65, 0x73, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xfc, 0x02, 0x54, 0xeb, 0xa6, 0x08,
    0xc1, 0xf3, 0x68, 0x70, 0xe2, 0x9a, 0xda, 0x90, 0xbe, 0x46, 0x38, 0x32, 0x92, 0x73, 0x6e, 0x89,
    0x4b, 0xff, 0xf6, 0x72, 0xd9, 0x89, 0x44, 0x4b, 0x50, 0x51, 0xe5, 0x34, 0xa4, 0xb1, 0xf6, 0xdb,
    0xe3, 0xc0, 0xbc, 0x58, 0x1a, 0x32, 0xb7, 0xb1, 0x76, 0x07, 0x0e, 0xde, 0x12, 0xd6, 0x9a, 0x3f,
    0xea, 0x21, 0x1b, 0x66, 0xe7, 0x52, 0xcf, 0x7d, 0xd1, 0xdd, 0x09, 0x5f, 0x6f, 0x13, 0x70, 0xf4,
    0x17, 0x08, 0x43, 0xd9, 0xdc, 0x10, 0x01, 0x21, 0xe4, 0xcf, 0x63, 0x01, 0x28, 0x09, 0x66, 0x44,
    0x87, 0xc9, 0x79, 0x62, 0x84, 0x30, 0x4d, 0xc5, 0x3f, 0xf4, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x90, 0x25, 0xb5, 0x0d, 0xd9, 0x05,
    0x47, 0xe7, 0x96, 0xc3, 0x96, 0xfa, 0x72, 0x9d, 0xcf, 0x99, 0xa9, 0xdf, 0x4b, 0x96, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x69, 0x00, 0x30, 0x66, 0x02,
    0x31, 0x00, 0xa3, 0x7f, 0x2f, 0x91, 0xa1, 0xc9, 0xbd, 0x5e, 0xe7, 0xb8, 0x62, 0x7c, 0x16, 0x98,
    0xd2, 0x55, 0x03, 0x8e, 0x1f, 0x03, 0x43, 0xf9, 0x5b, 0x63, 0xa9, 0x62, 0x8c, 0x3d, 0x39, 0x80,
    0x95, 0x45, 0xa1, 0x1e, 0xbc, 0xbf, 0x2e, 0x3b, 0x55, 0xd8, 0xae, 0xee, 0x71, 0xb4, 0xc3, 0xd6,
    0xad, 0xf3, 0x02, 0x31, 0x00, 0xa2, 0xf3, 0x9b, 0x16, 0x05, 0xb2, 0x70, 0x28, 0xa5, 0xdd, 0x4b,
    0xa0, 0x69, 0xb5, 0x01, 0x6e, 0x65, 0xb4, 0xfb, 0xde, 0x8f, 0xe0, 0x06, 0x1d, 0x6a, 0x53, 0x19,
    0x7f, 0x9c, 0xda, 0xf5, 0xd9, 0x43, 0xbc, 0x61, 0xfc, 0x2b, 0xeb, 0x03, 0xcb, 0x6f, 0xee, 0x8d,
    0x23, 0x02, 0xf3, 0xdf, 0xf6,
];

/// the following value was copied from https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/attestation.c
/// I've no idea where it came from (I've seen no documentation on this), but
/// I guess I have to trust Amazon on this one
const NSM_MAX_ATTESTATION_DOC_SIZE: usize = 16 * 1024;

lazy_static! {
    /// The (randomly) self-generated device key pair.
    /// Would like to have this stored as EcdsaKeyPair, instead of having
    /// to generate it from bytes each time, but EcdsaKeyPair doesn't support
    /// `copy` or `clone`, so it's hard to manage that way
    static ref DEVICE_KEY_PAIR: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    /// The hash value of the Runtime Manager enclave
    static ref RUNTIME_MANAGER_HASH: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    /// The Device ID assigned to us by the Proxy Attestation Service
    static ref DEVICE_ID: Mutex<Option<i32>> = std::sync::Mutex::new(None);
    static ref CERT_CHAIN: Mutex<Option<(Vec<u8>, Vec<u8>)>> = Mutex::new(None);
    static ref CHALLENGE_ID_COUNTER: AtomicI32 = AtomicI32::new(0);
    static ref CHALLENGE_HASHMAP: Mutex<HashMap<i32, Vec<u8>>> = Mutex::new(HashMap::new());
}

/// Query the enclave for its firmware version
fn get_firmware_version() -> Result<String, String> {
    println!("nitro-root-enclave::get_firmware_version");
    let version = env!("CARGO_PKG_VERSION");
    return Ok(version.to_string());
}

/// Perform the native attestation flow
fn native_attestation(challenge: &[u8], device_id: i32) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut att_doc: Vec<u8> = vec![0; NSM_MAX_ATTESTATION_DOC_SIZE];

    {
        let mut di_guard = DEVICE_ID.lock().map_err(|err| {
            format!(
                "nitro-root-enclave::native_attestation failed to obtain lock on DEVICE_ID:{:?}",
                err
            )
        })?;
        *di_guard = Some(device_id);
    }

    let mut att_doc_len: u32 = att_doc.len() as u32;
    let device_private_key: EcdsaKeyPair = get_device_key_pair()?;
    let csr = veracruz_utils::csr::generate_csr(&veracruz_utils::csr::ROOT_ENCLAVE_CSR_TEMPLATE, &device_private_key)
        .map_err(|err| format!("nitro-root-enclave::native_attestation generate_csr failed:{:?}", err))?;

    let nsm_fd = nsm_lib::nsm_lib_init();
    if nsm_fd < 0 {
        return Err(format!(
            "nitro-root-enclave::native_attestation nsm_lib_init failed:{:?}",
            nsm_fd
        ));
    }
    let status = unsafe {
        nsm_lib::nsm_get_attestation_doc(
            nsm_fd,                                     // fd
            csr.as_ptr() as *const u8,                  // user_data
            csr.len() as u32,                           // user_data_len
            challenge.as_ptr(),                         // nonce_data
            challenge.len() as u32,                     // nonce_len
            std::ptr::null(),                           // pub_key_data
            0,                                          // pub_key_len
            att_doc.as_mut_ptr(),                       // att_doc_data
            &mut att_doc_len,                           // att_doc_len
        )
    };
    match status {
        nsm_io::ErrorCode::Success => (),
        _ => return Err(format!("nitro-root-enclave::native_attestation received non-success error code from nsm_lib:{:?}", status)),
    }
    unsafe {
        att_doc.set_len(att_doc_len as usize);
    }
    return Ok((att_doc, csr.clone()));
}

fn set_cert_chain(re_cert: &[u8], ca_cert: &[u8]) -> Result<(), String> {
    let mut cc_guard = CERT_CHAIN.lock()
        .map_err(|err| format!("nitro-root-enclave:set_cert_chain failed to obtain lock on CERT_CHAIN:{:?}", err))?;
    *cc_guard = Some((re_cert.to_vec(), ca_cert.to_vec()));
    return Ok(());
}

/// Perform the proxy attestation service on behalf of a Runtime Manager enclave
/// running on another AWS Nitro Enclave
fn proxy_attestation(
    att_doc: &[u8],
    challenge_id: i32,
) -> Result<NitroRootEnclaveMessage, String> {
    // first authenticate the attestation document
    let document: AttestationDocument = match NitroToken::authenticate_token(att_doc, &AWS_NITRO_ROOT_CERTIFICATE) {
        Ok(data) => data,
        Err(err) => {
            println!("nitro-root-enclave::proxy_attestation authenticate_token failed:{:?}", err);
            return Ok(NitroRootEnclaveMessage::Status(NitroStatus::Fail));
        },
    };
    // check that the challenge in the attestation document matches the one we
    // generated
    // we call `remove` on the hash map because if the entry is there, we no
    // longer need it after this
    let expected_challenge = match CHALLENGE_HASHMAP.lock()
        .map_err(|err| format!("nitro-root-enclave::proxy_attestation failed to obtain lock on CHALLENGE_HASHMAP:{:?}", err))?
        .remove(&challenge_id) {
        Some(value) => value,
        None => {
            println!("nitro-root-enclave::proxy_attestation value for challenge_id:{:?} not found on CHALLENGE_HASHMAP", challenge_id);
            return Ok(NitroRootEnclaveMessage::Status(NitroStatus::Fail));
        },
    };
    // The document.nonce value is optional for Nitro Enclaves in general, but
    // required by us
    let received_challenge = match document.nonce {
        Some(data) => data,
        None => {
            println!("nitro-root-enclave::proxy_attestation attestation document did not contain a nonce value");
            return Ok(NitroRootEnclaveMessage::Status(NitroStatus::Fail));
        },
    };
    if expected_challenge != received_challenge {
        println!("nitro-root-enclave::proxy_attestation challenge values did not match");
        return Ok(NitroRootEnclaveMessage::Status(NitroStatus::Fail));
    }

    let csr: Vec<u8> = match document.user_data {
        Some(data) => data,
        None => {
            println!("nitro-root-enclave::proxy_attestation AttestationDocument does not contain user_data");
            return Ok(NitroRootEnclaveMessage::Status(NitroStatus::Fail));
        },
    };

    let private_key: EcdsaKeyPair = get_device_key_pair()?;
    // convert the CSR into a certificate
    let compute_enclave_cert = match csr::convert_csr_to_cert(&csr, &csr::COMPUTE_ENCLAVE_CERT_TEMPLATE, &document.pcrs[0][0..32], &private_key) {
        Ok(cert) => cert,
        Err(err) => {
            println!("nitro-root-enclave::proxy_attestation convert_csr_to_cert failed:{:?}", err);
            return Ok(NitroRootEnclaveMessage::Status(NitroStatus::Fail));
        },
    };

    let (root_enclave_cert, root_cert) = {
        let cc_guard = CERT_CHAIN.lock()
            .map_err(|err| format!("nitro-root-enclave::proxy_attestation failed to obtain lock on CERT_CHAIN:{:?}", err))?;
        match &*cc_guard {
            Some((re_cert, r_cert)) => (re_cert.clone(), r_cert.clone()),
            None => return Err(format!("nitro-root-enclave::proxy_attestation CERT_CHAIN is uninitialized")),
        }
    };

    return Ok(NitroRootEnclaveMessage::CertChain(vec![compute_enclave_cert, root_enclave_cert, root_cert]));
}

fn set_device_key_pair(pkcs8: &[u8]) -> Result<(), String> {
    let mut dkp_guard = DEVICE_KEY_PAIR.lock().map_err(|err| {
        format!(
            "nitro-root-enclave::set_device_key_pair failed to obtain lock on DEVICE_KEY_PAIR:{:?}",
            err
        )
    })?;
    *dkp_guard = Some(pkcs8.to_vec());
    return Ok(());
}

fn get_device_key_pair() -> Result<EcdsaKeyPair, String> {
    let dkp_guard = DEVICE_KEY_PAIR.lock()
        .map_err(|err| format!("nitro-root-enclave::proxy_attestation failed to obtain lock on DEVICE_KEY_PAIR:{:?}", err))?;
    let pkcs8_bytes = match &*dkp_guard {
        Some(bytes) => bytes.clone(),
        None => return Err(format!("nitro-root-enclave::proxy_attestation DEVICE_KEY_PAIR is uninitialized")),
    };
    return EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8_bytes)
        .map_err(|err| format!("nitro-root-enclave::proxy_attestation failed to convert pkcs8 bytes to EcdsaKeyPair:{:?}", err));
}

/// The main entry point for the Nitro Root enclave
fn main() -> Result<(), String> {
    // generate the device private key
    // Let's try it as an EC key, because RSA is like, old, man.
    let rng = SystemRandom::new();
    println!("nitro-root-enclave::main generating key with rng. Which will probably hang, because why wouldn't it?");
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|err| format!("Error generating PKCS-8:{:?}", err))?
        .as_ref()
        .to_vec();
    set_device_key_pair(&pkcs8_bytes)?;

    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| format!("nitro-root-enclave::main failed to create socket:{:?}", err))?;

    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind(socket_fd, &sockaddr)
        .map_err(|err| format!("nitro-root-enclave::main bind failed:{:?}", err))?;

    listen_vsock(socket_fd, BACKLOG)
        .map_err(|err| format!("nitro-root-enclave::main listen_vsock failed:{:?}", err))?;

    let fd = accept(socket_fd)
        .map_err(|err| format!("nitro-root-enclave::main accept failed:{:?}", err))?;
    loop {
        let received_buffer = receive_buffer(fd)
            .map_err(|err| format!("nitro-root-enclave::main receive_buffer failed:{:?}", err))?;
        println!("nitro-root-enclave::main received_buffer.len:{:?}", received_buffer.len());
        let received_message: NitroRootEnclaveMessage = bincode::deserialize(&received_buffer).map_err(|err| format!("nitro-root-enclave::main failed to parse received buffer as NitroRootEnclaveMessage:{:?}", err))?;
        let return_message = match received_message {
            NitroRootEnclaveMessage::FetchFirmwareVersion => {
                println!("nitro-root-enclave::main received FetchFirmwareVersion message");
                let version = get_firmware_version().map_err(|err| {
                    format!("nitro-root-enclave::main failed to get version:{:?}", err)
                })?;
                NitroRootEnclaveMessage::FirmwareVersion(version)
            }
            NitroRootEnclaveMessage::NativeAttestation(challenge, device_id) => {
                println!("nitro-root-enclave::main received NativeAttestaion message");
                let (proxy_token, csr) =
                    native_attestation(&challenge, device_id).map_err(|err| {
                        format!(
                            "nitro-root-enclave::main native_attestation failed:{:?}",
                            err
                        )
                    })?;
                NitroRootEnclaveMessage::TokenData(proxy_token, csr)
            }
            NitroRootEnclaveMessage::SetCertChain(re_cert, ca_cert) => {
                set_cert_chain(&re_cert, &ca_cert)?;
                // If we got thhis far, we have succeeded. Return a success message
                NitroRootEnclaveMessage::Success
            }
            NitroRootEnclaveMessage::StartProxy => {
                generate_challenge_data()?
            },
            NitroRootEnclaveMessage::ProxyAttestation(att_doc, challenge_id) => {
                println!("nitro-root-enclave::main received ProxyAttesstation message");
                proxy_attestation(&att_doc, challenge_id)?
            }
            _ => {
                println!("nitro-root-enclave::main received unhandled message:{:?}", received_message);
                return Err(format!(
                    "nitro-root-enclave::main received floopy unhandled message:{:?}",
                    received_message
                ))
            }
        };
        let return_buffer = bincode::serialize(&return_message).map_err(|err| {
            format!(
                "nitro-root-enclave::main failed to serialize return_message:{:?}",
                err
            )
        })?;

        send_buffer(fd, &return_buffer).map_err(|err| {
            format!(
                "nitro-root-enclave::main failed to send return_buffer:{:?}",
                err
            )
        })?;
    }
}

fn generate_challenge_data() -> Result<NitroRootEnclaveMessage, String> {
    let challenge_id = CHALLENGE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

    let mut challenge:Vec<u8> = Vec::with_capacity(16);
    let rng = SystemRandom::new();
    rng.fill(&mut challenge);
    {
        let mut chm_guard = CHALLENGE_HASHMAP.lock()
            .map_err(|err| format!("nitro-root-enclave::generate_challenge_data failed to obtain lock on CHALLENGE_HASHMAP:{:?}", err))?;
        chm_guard.insert(challenge_id, challenge.clone());
    }
    return Ok(NitroRootEnclaveMessage::ChallengeData(challenge, challenge_id));
}
