//! IceCap-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

extern crate alloc;

use crate::managers::session_manager;
use bincode;
use core::{convert::TryFrom, mem::size_of};
use icecap_core::{
    config::*,
    logger::{DisplayMode, Level, Logger},
    prelude::*,
    ring_buffer::*,
};
use icecap_start_generic::declare_generic_main;
use icecap_std_external;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use veracruz_utils::runtime_manager_message::{
    RuntimeManagerRequest, RuntimeManagerResponse, Status,
};

declare_generic_main!(main);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    event_nfn: Notification,
    virtio_console_server_ring_buffer: UnmanagedRingBufferConfig,
    badges: Badges,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Badges {
    virtio_console_server_ring_buffer: Badge,
}

fn main(config: Config) -> Fallible<()> {
    // TODO why do we need this?
    icecap_runtime_init();

    debug_println!("icecap-realmos: initializing...");

    // enable ring buffer to serial-server
    let virtio_console_client =
        RingBuffer::unmanaged_from_config(&config.virtio_console_server_ring_buffer);
    virtio_console_client.enable_notify_read();
    virtio_console_client.enable_notify_write();
    debug_println!("icecap-realmos: enabled ring buffer");

    debug_println!("icecap-realmos: running...");
    RuntimeManager::new(
        virtio_console_client,
        config.event_nfn,
        config.badges.virtio_console_server_ring_buffer,
    )
    .run()
}

struct RuntimeManager {
    channel: RingBuffer,
    event: Notification,
    virtio_console_server_ring_buffer_badge: Badge,
    active: bool,
}

impl RuntimeManager {
    fn new(
        channel: RingBuffer,
        event: Notification,
        virtio_console_server_ring_buffer_badge: Badge,
    ) -> Self {
        Self {
            channel: channel,
            event: event,
            virtio_console_server_ring_buffer_badge: virtio_console_server_ring_buffer_badge,
            active: true,
        }
    }

    fn run(&mut self) -> Fallible<()> {
        loop {
            let badge = self.event.wait();
            if badge & self.virtio_console_server_ring_buffer_badge != 0 {
                self.process()?;
                self.channel.enable_notify_read();
                self.channel.enable_notify_write();

                if !self.active {
                    return Ok(());
                }
            }
        }
    }

    fn process(&mut self) -> Fallible<()> {
        // recv request if we have a full request in our ring buffer
        if self.channel.poll_read() < size_of::<u32>() {
            return Ok(());
        }
        let mut raw_header = [0; size_of::<u32>()];
        self.channel.peek(&mut raw_header);
        let header = bincode::deserialize::<u32>(&raw_header)
            .map_err(|e| format_err!("Failed to deserialize request: {}", e))?;
        let size = usize::try_from(header)
            .map_err(|e| format_err!("Failed to deserialize request: {}", e))?;

        if self.channel.poll_read() < size_of::<u32>() + size {
            return Ok(());
        }
        let mut raw_request = vec![0; usize::try_from(header).unwrap()];
        self.channel.skip(size_of::<u32>());
        self.channel.read(&mut raw_request);
        let request = bincode::deserialize::<RuntimeManagerRequest>(&raw_request)
            .map_err(|e| format_err!("Failed to deserialize request: {}", e))?;

        // process requests
        let response = self.handle(request)?;

        // send response
        let raw_response = bincode::serialize(&response)
            .map_err(|e| format_err!("Failed to serialize response: {}", e))?;
        let raw_header = bincode::serialize(&u32::try_from(raw_response.len()).unwrap())
            .map_err(|e| format_err!("Failed to serialize response: {}", e))?;

        self.channel.write(&raw_header);
        self.channel.write(&raw_response);

        self.channel.notify_read();
        self.channel.notify_write();

        Ok(())
    }

    fn handle(&mut self, req: RuntimeManagerRequest) -> Fallible<RuntimeManagerResponse> {
        Ok(match req {
            RuntimeManagerRequest::Attestation(challenge, device_id) => {
                match session_manager::init_session_manager()
                    .and(self.handle_attestation(device_id, &challenge))
                {
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    Ok((token, csr)) => RuntimeManagerResponse::AttestationData(token, csr),
                }
            }
            RuntimeManagerRequest::Initialize(policy_json, cert_chain) => {
                match session_manager::load_policy(&policy_json)
                    .and(session_manager::load_cert_chain(&cert_chain))
                {
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    Ok(()) => RuntimeManagerResponse::Status(Status::Success),
                }
            }
            RuntimeManagerRequest::NewTlsSession => match session_manager::new_session() {
                Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                Ok(sess) => RuntimeManagerResponse::TlsSession(sess),
            },
            RuntimeManagerRequest::CloseTlsSession(sess) => {
                match session_manager::close_session(sess) {
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    Ok(()) => RuntimeManagerResponse::Status(Status::Success),
                }
            }
            RuntimeManagerRequest::SendTlsData(sess, data) => {
                match session_manager::send_data(sess, &data) {
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    Ok(()) => RuntimeManagerResponse::Status(Status::Success),
                }
            }
            RuntimeManagerRequest::GetTlsDataNeeded(sess) => {
                match session_manager::get_data_needed(sess) {
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    Ok(needed) => RuntimeManagerResponse::TlsDataNeeded(needed),
                }
            }
            RuntimeManagerRequest::GetTlsData(sess) => match session_manager::get_data(sess) {
                Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                Ok((active, data)) => {
                    self.active = active;
                    RuntimeManagerResponse::TlsData(data, active)
                }
            },
        })
    }

    fn handle_attestation(
        &self,
        _device_id: Uuid,
        challenge: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let csr = session_manager::generate_csr()?;
        let token = attestation_hack::native_attestation(&challenge, &csr)?;
        Ok((token, csr))
    }
}

const LOG_LEVEL: Level = Level::Error;

// HACK
// System time is provided at build time. The same time is provided to the test Linux userland.
// These must align with each other and with the time the test policies were generated.
const NOW: u64 = include!("../../NOW");

fn icecap_runtime_init() {
    icecap_std_external::early_init();
    icecap_std_external::set_now(std::time::Duration::from_secs(NOW));
    let mut logger = Logger::default();
    logger.level = LOG_LEVEL;
    logger.display_mode = DisplayMode::Line;
    logger.write = |s| debug_println!("{}", s);
    logger.init().unwrap();
}

// HACK
// Attestation not yet implemented in IceCap itself.
mod attestation_hack {

    use veracruz_utils::sha256::sha256;

    const EXAMPLE_PUBLIC_KEY: [u8; 65] = [
        0x4, 0x5f, 0x5, 0x5d, 0x39, 0xd9, 0xad, 0x60, 0x89, 0xf1, 0x33, 0x7e, 0x6c, 0xf9, 0x57,
        0xe, 0x6f, 0x84, 0x25, 0x5f, 0x16, 0xf8, 0xcd, 0x9c, 0xe4, 0xa0, 0xa2, 0x8d, 0x7a, 0x4f,
        0xb7, 0xe4, 0xd3, 0x60, 0x37, 0x2a, 0x81, 0x4f, 0x7, 0xc2, 0x5a, 0x24, 0x85, 0xbf, 0x47,
        0xbc, 0x84, 0x47, 0x40, 0xc5, 0x9b, 0xff, 0xff, 0xd2, 0x76, 0x32, 0x82, 0x4d, 0x76, 0x4d,
        0xb4, 0x50, 0xee, 0x9f, 0x22,
    ];

    const EXAMPLE_PRIVATE_KEY: [u8; 32] = [
        0xe6, 0xbf, 0x1e, 0x3d, 0xb4, 0x45, 0x42, 0xbe, 0xf5, 0x35, 0xe7, 0xac, 0xbc, 0x2d, 0x54,
        0xd0, 0xba, 0x94, 0xbf, 0xb5, 0x47, 0x67, 0x2c, 0x31, 0xc1, 0xd4, 0xee, 0x1c, 0x05, 0x76,
        0xa1, 0x44,
    ];

    const EXAMPLE_HASH: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
        0xef, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d, 0xca, 0xfe, 0xf0, 0x0d,
        0xca, 0xfe,
    ];

    const ROOT_PRIVATE_KEY: &[u8] = &EXAMPLE_PRIVATE_KEY;

    const RUNTIME_MANAGER_HASH: &[u8] = &EXAMPLE_HASH;

    /// Stub attestation handler
    pub(super) fn native_attestation(challenge: &[u8], csr: &[u8]) -> anyhow::Result<Vec<u8>> {
        let root_private_key = &ROOT_PRIVATE_KEY;
        let enclave_hash = &RUNTIME_MANAGER_HASH;
        let csr_hash = sha256(csr);

        let mut root_key_handle: u32 = 0;
        assert_eq!(0, unsafe {
            psa_attestation::psa_initial_attest_load_key(
                root_private_key.as_ptr(),
                root_private_key.len() as u64,
                &mut root_key_handle,
            )
        });

        // Section 3.2.1 of https://www.ietf.org/archive/id/draft-tschofenig-rats-psa-token-09.txt
        // EAT UEID of type RAND.
        // Length must be 33 bytes
        // first byte MUST be 0x01 (RAND)
        // next 32 bytes must be the hash of the key (Is this the public or private key? It's unclear, presume the public key because a hash of the private key could theoretically bleed info
        // about the private key)
        let public_key_hash = sha256(&EXAMPLE_PUBLIC_KEY);
        let mut enclave_name: Vec<u8> = Vec::new();
        enclave_name.push(0x01);
        enclave_name.extend_from_slice(&public_key_hash);

        let mut token: Vec<u8> = Vec::with_capacity(2048);
        let mut token_len: u64 = 0;
        assert_eq!(0, unsafe {
            psa_attestation::psa_initial_attest_get_token(
                enclave_hash.as_ptr() as *const u8,
                enclave_hash.len() as u64,
                csr_hash.as_ptr() as *const u8,
                csr_hash.len() as u64,
                enclave_name.as_ptr() as *const u8,
                enclave_name.len() as u64,
                challenge.as_ptr() as *const u8,
                challenge.len() as u64,
                token.as_mut_ptr() as *mut u8,
                token.capacity() as u64,
                &mut token_len as *mut u64,
            )
        });
        unsafe { token.set_len(token_len as usize) };

        assert_eq!(0, unsafe {
            psa_attestation::psa_initial_attest_remove_key(root_key_handle)
        });

        Ok(token)
    }
}

// Dependencies depend on these C symbols. We define them here in Rust.
mod c_hack {

    use super::alloc::boxed::Box;

    #[no_mangle]
    extern "C" fn fmod(x: f64, y: f64) -> f64 {
        libm::fmod(x, y)
    }

    #[no_mangle]
    extern "C" fn fmodf(x: f32, y: f32) -> f32 {
        libm::fmodf(x, y)
    }

    #[no_mangle]
    extern "C" fn calloc(nelem: usize, elsize: usize) -> *mut core::ffi::c_void {
        let bytes = nelem * elsize;
        // TODO use Box::<[u8]>::new_zeroed_slice(bytes) instead after bumping rustc
        let ret: *mut [u8] = Box::into_raw(vec![0; bytes].into_boxed_slice());
        ret as *mut core::ffi::c_void
    }

    #[no_mangle]
    extern "C" fn free(ptr: *mut core::ffi::c_void) {
        if !ptr.is_null() {
            unsafe {
                // TODO is this sound?
                Box::<u8>::from_raw(ptr as *mut u8);
            }
        }
    }
}
