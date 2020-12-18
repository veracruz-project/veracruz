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
use psa_attestation::{psa_initial_attest_get_token, psa_initial_attest_load_key, t_cose_sign1_get_verification_pubkey};
use ring;
use ring::signature::KeyPair;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use std::sync::Mutex;
use veracruz_utils::{NitroRootEnclaveMessage, NitroStatus};

use veracruz_utils::{receive_buffer, send_buffer};

use nsm_io;
use nsm_lib;

//const CID: u32 = 17;
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
const PORT: u32 = 5005;
// Maximum number of outstanding connections in the socket's
// listen queue
const BACKLOG: usize = 128;

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

// the following value was copied from https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/attestation.c
// I've no idea where it came from (I've seen no documentation on this), but
// I guess I have to trust Amazon on this one
const NSM_MAX_ATTESTATION_DOC_SIZE: usize = 16 * 1024;

lazy_static! {
    static ref DEVICE_KEY_PAIR: Mutex<Option<(EcdsaKeyPair, Vec<u8>)>> = Mutex::new(None);
    static ref MEXICO_CITY_HASH: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    static ref DEVICE_ID: Mutex<Option<i32>> = std::sync::Mutex::new(None);
}

fn get_firmware_version() -> Result<String, String> {
    println!("nitro-root-enclave::get_firmware_version");
    let version = env!("CARGO_PKG_VERSION");
    return Ok(version.to_string());
}

fn set_mexico_city_hash_hack(hash: Vec<u8>) -> Result<NitroStatus, String> {
    let mut mch_guard = MEXICO_CITY_HASH.lock().map_err(|err| {
        format!(
            "set_mexico_city_hash failed to obtain lock on MEXICO_CITY_HASH:{:?}",
            err
        )
    })?;
    *mch_guard = Some(hash);
    Ok(NitroStatus::Success)
}

fn native_attestation(challenge: &Vec<u8>, device_id: i32) -> Result<(Vec<u8>, Vec<u8>), String> {
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
    let device_private_key = {
        let dkp_guard = DEVICE_KEY_PAIR.lock().map_err(|err| format!("nitro-root-enclave::native_attestation failed to obtain lock on DEVICE_KEY_PAIR:{:?}", err))?;
        match &*dkp_guard {
            Some((_key, bytes)) => bytes.clone(),
            None => return Err(format!("nitro-root-enclave::native_attestation for some reason the DEVICE_KEY_PAIR is uninitialized. I don't know how you got here")),
        }
    };
    let device_public_key = {
        // Oddity: the current way of extracting the public key from the private
        // key is to load it into PSA Crytpo, and then extract the public
        // component. There are better ways to do this, but this is what
        // I know to do now. It's ugly, but it works, but there are 
        // better ways
        let mut device_key_handle: u16 = 0;
        let status = unsafe {
            psa_initial_attest_load_key(
                device_private_key.as_ptr(),
                device_private_key.len() as u64,
                &mut device_key_handle,
            )
        };
        if status != 0 {
            println!("jalisco::create psa_initial_attest_load_key failed to load device private key with code:{:}", status);
            return Err(format!("jalisco::create psa_initial_attest_load_key failed to load device private key with code:{:}", status));
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
            println!(
                "jalisco::create t_cose_sign1_get_verification_pubkey failed with error code:{:}",
                status
            );
            return Err(format!(
                "jalisco::create t_cose_sign1_get_verification_pubkey failed with error code:{:}",
                status
            ));
        }
        unsafe {
            public_key.set_len(public_key_size as usize);
        }
        public_key
    };

    let nsm_fd = nsm_lib::nsm_lib_init();
    if nsm_fd < 0 {
        return Err(format!(
            "nitro-root-enclave::native_attestation nsm_lib_init failed:{:?}",
            nsm_fd
        ));
    }
    let status = unsafe {
        nsm_lib::nsm_get_attestation_doc(
            nsm_fd,                                     //fd
            std::ptr::null(),                           // user_data
            0,                                          // user_data_len
            challenge.as_ptr(),                         // nonce_data
            challenge.len() as u32,                     // nonce_len
            device_public_key.as_ptr() as *const u8,    // pub_key_data
            device_public_key.len() as u32,             // pub_key_len
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
    println!(
        "nitro-root-enclave::main::native_attestation returning token:{:?}",
        att_doc
    );
    return Ok((att_doc, device_public_key.to_vec()));
}

fn proxy_attestation(
    challenge: &Vec<u8>,
    native_token: &Vec<u8>,
    enclave_name: String,
) -> Result<Vec<u8>, String> {
    // first authenticate the native token
    let document: AttestationDocument =
        NitroToken::authenticate_token(native_token, &AWS_NITRO_ROOT_CERTIFICATE).map_err(
            |err| {
                format!(
                    "nitro-root-enclave::proxy_attestation failed to authenticate token:{:?}",
                    err
                )
            },
        )?;
    let enclave_cert_hash: Vec<u8> = match document.user_data {
        Some(hash) => hash,
        None => return Err(format!("nitro-root-enclave::proxy_attestation AttestationDocument does not contain user_data")),
    };

    // load the PSA key into PSA Crypto
    let device_private_key = {
        let dkp_guard = DEVICE_KEY_PAIR.lock()
            .map_err(|err| format!("ntiro-root-enclave:proxy_attestation failed to obtain lock on DEVICE_KEY_PAIR:{:?}", err))?;
        match &*dkp_guard {
            Some((_key, bytes)) => bytes.clone(),
            None => {
                return Err(format!(
                    "nitro-root-enclave::proxy_attestation Device Key pair is not populated?"
                ))
            }
        }
    };
    let mut device_key_handle: u16 = 0;
    let status = unsafe {
        psa_initial_attest_load_key(
            device_private_key.as_ptr(),
            device_private_key.len() as u64,
            &mut device_key_handle,
        )
    };
    if status != 0 {
        return Err(format!("nitro-root-enclave:proxy_attestation psa_initial_attest_load_key failed with status code:{:?}", status));
    }
    // generate the PSA Attestation token using challenge, measurement from the native token, and the enclave_cert_hash
    let mut token: Vec<u8> = Vec::with_capacity(2048); // TODO: Don't do this
    let mut token_len: u64 = 0;
    let enclave_name_len: usize = enclave_name.len();
    // AWS Nitro PCRs are SHA384 hashes. The rest of our hashes are SHA256.
    // We are truncating it in the PSA token so the offsets don't change between
    // platforms
    let pcr_len: u64 = if document.pcrs[0].len() > 32 {
        32
    } else {
        return Err(format!(
            "nitro-root-enclave:proxy_attestation document.pcrs[0] is too short. Wanted > 32, got:{:?}", document.pcrs[0].len()
        ));
    };
    let status = unsafe {
        psa_initial_attest_get_token(
            document.pcrs[0].as_ptr() as *const u8,
            pcr_len as u64,
            enclave_cert_hash.as_ptr() as *const u8, // user_data in the document is the certificate hash
            enclave_cert_hash.len() as u64,
            enclave_name.into_bytes().as_ptr() as *const i8,
            enclave_name_len as u64,
            challenge.as_ptr() as *const u8,
            challenge.len() as u64,
            token.as_mut_ptr() as *mut u8,
            2048,
            &mut token_len as *mut u64,
        )
    };
    if status != 0 {
        return Err(format!("nitro-root-enclave::proxy_attestation psa_initial_attest_get_token failed with error code:{:?}", status));
    }
    unsafe { token.set_len(token_len as usize) };

    // return the proxy token
    Ok(token.clone())
}

fn main() -> Result<(), String> {
    // generate the device private key
    // Let's try it as an EC key, because RSA is like, old, man.
    let rng = ring::rand::SystemRandom::new();
    println!("nitro-root-enclave::main generating key with rng. Which will probably hang, because why wouldn't it?");
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|err| format!("Error generating PKCS-8:{:?}", err))?
        .as_ref()
        .to_vec();
    println!("nitro-root-enclave::main successfully generated key with rng. What the F do I know? I'm just a computer");
    let device_key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes)
        .map_err(|err| format!("nitro-root-enclave::main from_pkcs8 failed:{:?}", err))?;
    {
        let mut dkp_guard = DEVICE_KEY_PAIR.lock().map_err(|err| {
            format!(
                "nitro-root-enclave::main failed to obtain lock on DEVICE_KEY_PAIR:{:?}",
                err
            )
        })?;
        *dkp_guard = Some((device_key_pair, pkcs8_bytes[38..70].to_vec()));
    }

    println!(
        "nitro-root-enclave::main successfully did the stupid plkcs8 to \"internal\" conversion."
    );
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
            NitroRootEnclaveMessage::SetMexicoCityHashHack(hash) => {
                let status = set_mexico_city_hash_hack(hash)?;
                NitroRootEnclaveMessage::Status(status)
            }
            NitroRootEnclaveMessage::NativeAttestation(challenge, device_id) => {
                println!("nitro-root-enclave::main received NativeAttestaion message");
                let (proxy_token, public_key) =
                    native_attestation(&challenge, device_id).map_err(|err| {
                        format!(
                            "nitro-root-enclave::main native_attestation failed:{:?}",
                            err
                        )
                    })?;
                NitroRootEnclaveMessage::TokenData(proxy_token, public_key)
            }
            NitroRootEnclaveMessage::ProxyAttestation(challenge, native_token, enclave_name) => {
                println!("nitro-root-enclave::main received ProxyAttesstation message");
                let proxy_token = proxy_attestation(&challenge, &native_token, enclave_name)
                    .map_err(|err| {
                        println!("proxy_attestation failed");
                        format!(
                            "nitro-root-enclave::main proxy_attestation failed:{:?}",
                            err
                        )
                    })?;
                let device_id: i32 = {
                    let di_guard = DEVICE_ID.lock().map_err(|err| {
                        println!("Failed to obtain lock on DEVICE_ID");
                        format!(
                            "nitro-root-enclave::main failed to obtain lock on DEVICE_ID:{:?}",
                            err
                        )
                    })?;
                    match &*di_guard {
                        Some(did) => *did,
                        None => {
                            return Err(format!(
                                "nitro-root-enclave::main DEVICE_ID is not set up?"
                            ))
                        }
                    }
                };
                let device_private_key = {
                    let dkp_guard = DEVICE_KEY_PAIR.lock()
                        .map_err(|err| format!("ntiro-root-enclave:proxy_attestation failed to obtain lock on DEVICE_KEY_PAIR:{:?}", err))?;
                    match &*dkp_guard {
                        Some((_key, bytes)) => bytes.clone(),
                        None => {
                            return Err(format!(
                                "nitro-root-enclave::proxy_attestation Device Key pair is not populated?"
                            ))
                        }
                    }
                };
                let device_public_key = {
                    // Oddity: the current way of extracting the public key from the private
                    // key is to load it into PSA Crytpo, and then extract the public
                    // component. There are better ways to do this, but this is what
                    // I know to do now. It's ugly, but it works, but there are 
                    // better ways
                    let mut device_key_handle: u16 = 0;
                    println!("Starting with device_private_key value:{:?}", device_private_key);
                    let status = unsafe {
                        psa_initial_attest_load_key(
                            device_private_key.as_ptr(),
                            device_private_key.len() as u64,
                            &mut device_key_handle,
                        )
                    };
                    if status != 0 {
                        println!("jalisco::create psa_initial_attest_load_key failed to load device private key with code:{:}", status);
                        return Err(format!("nitro-root-enclave::proxy_attestation psa_initial_attest_load_key failed to load key with code:{:?}", status));
                    }
                    println!("nitro-root-enclave::proxy_attestation device_key_handle:{:?}", device_key_handle);
                    let mut public_key = std::vec::Vec::with_capacity(1024); // TODO: Don't do this
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
                        println!(
                            "jalisco::create t_cose_sign1_get_verification_pubkey failed with error code:{:}",
                            status
                        );
                        return Err(format!(
                            "jalisco::create t_cose_sign1_get_verification_pubkey failed with error code:{:}",
                            status
                        ));
                    }
                    println!("nitro-root-enclave::main public_key_size:{:?}", public_key_size);
                    unsafe {
                        public_key.set_len(public_key_size as usize);
                    }
                    println!("nitro-root-enclave::main returning public_key value:{:?}", public_key);
                    public_key.clone()
                };
                println!("nitro-root-enclave::main finished handling proxy attestation message");
                NitroRootEnclaveMessage::PSAToken(proxy_token, device_public_key, device_id as u32)
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
        println!(
            "nitro-root-enclave::main returning return_buffer:{:?}",
            return_buffer
        );
        send_buffer(fd, &return_buffer).map_err(|err| {
            format!(
                "nitro-root-enclave::main failed to send return_buffer:{:?}",
                err
            )
        })?;
    }
}
