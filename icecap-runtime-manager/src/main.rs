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

#![feature(rustc_private)]
#![no_main]
#![feature(format_args_nl)]
extern crate alloc;

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
use runtime_manager::{
    common_runtime::CommonRuntime,
};
use serde::{Deserialize, Serialize};

mod icecap_runtime;

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

fn  main(config: Config) -> Fallible<()> {
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
        let icecap_runtime = icecap_runtime::IcecapRuntime{};

        println!("icecap_runtime_manager::linux_main accept run looping");
        let mut runtime = CommonRuntime::new(&icecap_runtime);
        loop {
            let badge = self.event.wait();
            if badge & self.virtio_console_server_ring_buffer_badge != 0 {
                self.process(&mut runtime)?;
                self.channel.enable_notify_read();
                self.channel.enable_notify_write();

                if !self.active {
                    return Ok(());
                }
            }
        }
    }

    fn process(&mut self, runtime: &mut CommonRuntime) -> Fallible<()> {
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
        // let request = bincode::deserialize::<RuntimeManagerRequest>(&raw_request)
        //     .map_err(|e| format_err!("Failed to deserialize request: {}", e))?;

        // process requests
        //let response = self.handle(request)?;
        let response_buffer = runtime.decode_dispatch(&raw_request)
            .map_err(|err| format_err!("runtime.decode_dispatch failed: {}", err))?;

        // send response
        // let raw_response = bincode::serialize(&response_buffer)
        //     .map_err(|e| format_err!("Failed to serialize response: {}", e))?;
        let raw_header = bincode::serialize(&u32::try_from(response_buffer.len()).unwrap())
            .map_err(|e| format_err!("Failed to serialize response: {}", e))?;

        self.channel.write(&raw_header);
        self.channel.write(&response_buffer);

        self.channel.notify_read();
        self.channel.notify_write();

        Ok(())
    }
}

const LOG_LEVEL: Level = Level::Error;

// HACK
// System time is provided at build time. The same time is provided to the test Linux userland.
// These must align with each other and with the time the test policies were generated.
const NOW: u64 = include!("../NOW");

fn icecap_runtime_init() {
    icecap_std_external::early_init();
    icecap_std_external::set_now(std::time::Duration::from_secs(NOW));
    let mut logger = Logger::default();
    logger.level = LOG_LEVEL;
    logger.display_mode = DisplayMode::Line;
    logger.write = |s| debug_println!("{}", s);
    logger.init().unwrap();
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
