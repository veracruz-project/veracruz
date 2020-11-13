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

use byteorder::{ByteOrder, LittleEndian};
use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, SockAddr};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use veracruz_utils::{NitroRootEnclaveMessage, NitroStatus};
use lazy_static::lazy_static;
use std::sync::Mutex;
use ring;
use ring::signature::{ EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING };
use ring::signature::KeyPair;

use veracruz_utils::{ receive_buffer, send_buffer };

use nsm_lib;
use nsm_io;

//const CID: u32 = 17;
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
const PORT: u32 = 5005;
// Maximum number of outstanding connections in the socket's
// listen queue
const BACKLOG: usize = 128;

// the following value was copied from https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/attestation.c
// I've no idea where it came from (I've seen no documentation on this), but 
// I guess I have to trust Amazon on this one
const NSM_MAX_ATTESTATION_DOC_SIZE: usize =  (16 * 1024);

lazy_static! {
    static ref DEVICE_KEY_PAIR: Mutex<Option<EcdsaKeyPair>> = Mutex::new(None);
    static ref MEXICO_CITY_HASH: Mutex<Option<Vec<u8>>> = Mutex::new(None);
}

fn get_firmware_version() -> Result<String, String> {
    println!("nitro-root-enclave::get_firmware_version");
    let version = env!("CARGO_PKG_VERSION");
    return Ok(version.to_string());
}

fn set_mexico_city_hash_hack(hash: Vec<u8>) -> Result<NitroStatus, String> {
    let mut mch_guard = MEXICO_CITY_HASH.lock().map_err(|err| format!("set_mexico_city_hash failed to obtain lock on MEXICO_CITY_HASH:{:?}", err))?;
    *mch_guard = Some(hash);
    Ok(NitroStatus::Success)
}

fn native_attestation(challenge: &Vec<u8>, device_id: i32) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut att_doc: Vec<u8> = vec![0; NSM_MAX_ATTESTATION_DOC_SIZE];

    let mut att_doc_len: u32 = att_doc.len() as u32;
    let device_public_key = {
        let dkp_guard = DEVICE_KEY_PAIR.lock().map_err(|err| format!("nitro-root-enclave::native_attestation failed to obtain lock on DEVICE_KEY_PAIR:{:?}", err))?;
        match &*dkp_guard {
            Some(key) => key.public_key().clone(),
            None => return Err(format!("nitro-root-enclave::native_attestation for some reason the DEVICE_KEY_PAIR is uninitialized. I don't know how you got here")),
        }
    };

    let nsm_fd = nsm_lib::nsm_lib_init();
    if nsm_fd < 0 {
        return Err(format!("nitro-root-enclave::native_attestation nsm_lib_init failed:{:?}", nsm_fd));
    }
    let status = unsafe {
        nsm_lib::nsm_get_attestation_doc(
            nsm_fd, //fd
            std::ptr::null(), // user_data
            0, // user_data_len
            challenge.as_ptr(), // nonce_data
            challenge.len() as u32, // nonce_len
            &device_public_key.as_ref()[0], // pub_key_data
            device_public_key.as_ref().len() as u32, // pub_key_len
            att_doc.as_mut_ptr(), // att_doc_data
            &mut att_doc_len, // att_doc_len
        )
    };
    match status {
        nsm_io::ErrorCode::Success => (),
        _ => return Err(format!("nitro-root-enclave::native_attestation received non-success error code from nsm_lib:{:?}", status)),
    }
    unsafe {
        att_doc.set_len(att_doc_len as usize);
    }
    println!("nitro-root-enclave::main::native_attestation returning token:{:?}", att_doc);
    return Ok((att_doc, device_public_key.as_ref().to_vec()));
}

fn main() -> Result<(), String> {
    // generate the device private key
    // Let's try it as an EC key, because RSA is like, old, man.
    let rng = ring::rand::SystemRandom::new();
    println!("nitro-root-enclave::main generating key with rng. Which will probably hang, because why wouldn't it?");
    let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|err| {
            format!("Error generating PKCS-8:{:?}", err)
        })?
        .as_ref().to_vec();
    println!("nitro-root-enclave::main successfully generated key with rng. What the F do I know? I'm just a computer");
    let device_key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes)
        .map_err(|err| {
            format!("nitro-root-enclave::main from_pkcs8 failed:{:?}", err)
        })?;
    {
        let mut dkp_guard = DEVICE_KEY_PAIR.lock().map_err(|err| {
            format!("nitro-root-enclave::main failed to obtain lock on DEVICE_KEY_PAIR:{:?}", err)
        })?;
        *dkp_guard = Some(device_key_pair);
    }

    println!("nitro-root-enclave::main successfully did the stupid plkcs8 to \"internal\" conversion.");
    let socket_fd = socket( AddressFamily::Vsock, SockType::Stream, SockFlag::empty(), None)
        .map_err(|err| format!("nitro-root-enclave::main failed to create socket:{:?}", err))?;

    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind(socket_fd, &sockaddr).map_err(|err| format!("nitro-root-enclave::main bind failed:{:?}", err))?;

    listen_vsock(socket_fd, BACKLOG)
        .map_err(|err| format!("nitro-root-enclave::main listen_vsock failed:{:?}", err))?;

    let fd =
        accept(socket_fd).map_err(|err| format!("nitro-root-enclave::main accept failed:{:?}", err))?;
    loop {
        let received_buffer = receive_buffer(fd)
            .map_err(|err| format!("nitro-root-enclave::main receive_buffer failed:{:?}", err))?;
        let received_message: NitroRootEnclaveMessage = bincode::deserialize(&received_buffer).map_err(|err| format!("nitro-root-enclave::main failed to parse received buffer as NitroRootEnclaveMessage:{:?}", err))?;
        let return_message = match received_message {
            NitroRootEnclaveMessage::FetchFirmwareVersion => {
                let version = get_firmware_version().map_err(|err| format!("nitro-root-enclave::main failed to get version:{:?}", err))?;
                NitroRootEnclaveMessage::FirmwareVersion(version)
            },
            NitroRootEnclaveMessage::SetMexicoCityHashHack(hash) => {
                let status = set_mexico_city_hash_hack(hash)?;
                NitroRootEnclaveMessage::Status(status)
            },
            NitroRootEnclaveMessage::NativeAttestation(challenge, device_id) => {
                let (token, public_key) = native_attestation(&challenge, device_id).map_err(|err| format!("nitro-root-enclave::main native_attestation failed:{:?}", err))?;
                NitroRootEnclaveMessage::TokenData(token, public_key) 
            },
            _ => return Err(format!("nitro-root-enclave::main received floopy unhandled message:{:?}", received_message)),
        };
        let return_buffer = bincode::serialize(&return_message).map_err(|err| format!("nitro-root-enclave::main failed to serialize return_message:{:?}", err))?;
        println!("nitro-root-enclave::main returning return_buffer:{:?}", return_buffer);
        send_buffer(fd, &return_buffer).map_err(|err| format!("nitro-root-enclave::main failed to send return_buffer:{:?}", return_buffer))?;
    }
}
