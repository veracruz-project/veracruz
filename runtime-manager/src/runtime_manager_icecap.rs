//! IceCap-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

extern crate alloc;

use std::string::ToString;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};

use icecap_core::prelude::*;
use icecap_core::config::RingBufferConfig;
use icecap_core::logger::{Logger, Level, DisplayMode};
use icecap_start_generic::declare_generic_main;

use veracruz_utils::platform::icecap::message::{Request, Response, Error};

use crate::managers::session_manager;

declare_generic_main!(main);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    host_ring_buffer: RingBufferConfig,
}

fn main(config: Config) -> Fallible<()> {
    icecap_runtime_init();
    let host_ring_buffer = RingBuffer::realize_resume(&config.host_ring_buffer);
    let host_ring_buffer_notification = config.host_ring_buffer.wait;
    RuntimeManager::new(host_ring_buffer, host_ring_buffer_notification).run()
}

struct RuntimeManager {
    host_ring_buffer: PacketRingBuffer,
    host_ring_buffer_notification: Notification,
    active: bool,
}

impl RuntimeManager {

    fn new(host_ring_buffer: RingBuffer, host_ring_buffer_notification: Notification) -> Self {
        host_ring_buffer.enable_notify_read();
        host_ring_buffer.enable_notify_write();
        Self {
            host_ring_buffer: PacketRingBuffer::new(host_ring_buffer),
            host_ring_buffer_notification,
            active: true,
        }
    }

    fn run(&mut self) -> Fallible<()> {
        loop {
            let req = self.recv()?;
            let resp = self.handle(&req)?;
            self.send(&resp)?;
            if !self.active {
                std::icecap_impl::external::runtime::exit();
            }
        }
    }

    fn handle(&mut self, req: &Request) -> Fallible<Response> {
        Ok(match req {
            Request::New { policy_json } => {
                session_manager::init_session_manager(&policy_json).unwrap();
                Response::New
            }
            Request::GetEnclaveCert => {
                match session_manager::get_enclave_cert_pem() {
                    Err(s) => {
                        log::debug!("{}", s);
                        Response::Error(Error::Unspecified)
                    }
                    Ok(cert) => {
                        Response::GetEnclaveCert(cert)
                    }
                }
            }
            Request::GetEnclaveName => {
                match session_manager::get_enclave_name() {
                    Err(s) => {
                        log::debug!("{}", s);
                        Response::Error(Error::Unspecified)
                    }
                    Ok(name) => {
                        Response::GetEnclaveName(name)
                    }
                }
            }
            Request::NewTlsSession => {
                match session_manager::new_session() {
                    Err(s) => {
                        log::debug!("{}", s);
                        Response::Error(Error::Unspecified)
                    }
                    Ok(sess) => {
                        Response::NewTlsSession(sess)
                    }
                }
            }
            Request::CloseTlsSession(sess) => {
                match session_manager::close_session(*sess) {
                    Err(s) => {
                        log::debug!("{}", s);
                        Response::Error(Error::Unspecified)
                    }
                    Ok(()) => {
                        Response::CloseTlsSession
                    }
                }
            }
            Request::SendTlsData(sess, data) => {
                match session_manager::send_data(*sess, data) {
                    Err(s) => {
                        log::debug!("{}", s);
                        Response::Error(Error::Unspecified)
                    }
                    Ok(()) => {
                        Response::SendTlsData
                    }
                }
            }
            Request::GetTlsDataNeeded(sess) => {
                match session_manager::get_data_needed(*sess) {
                    Err(s) => {
                        log::debug!("{}", s);
                        Response::Error(Error::Unspecified)
                    }
                    Ok(needed) => {
                        Response::GetTlsDataNeeded(needed)
                    }
                }
            }
            Request::GetTlsData(sess) => {
                match session_manager::get_data(*sess) {
                    Err(s) => {
                        log::debug!("{}", s);
                        Response::Error(Error::Unspecified)
                    }
                    Ok((active, data)) => {
                        self.active = active;
                        Response::GetTlsData(active, data)
                    }
                }
            }
        })
    }

    fn send(&mut self, resp: &Response) -> Fallible<()> {
        let resp_bytes = serialize(resp).unwrap();
        while !self.host_ring_buffer.write(&resp_bytes) {
            log::debug!("host ring buffer full, waiting on notification");
            self.host_ring_buffer_notification.wait();
        }
        self.host_ring_buffer.notify_write();
        Ok(())
    }

    fn recv(&mut self) -> Fallible<Request> {
        loop {
            if let Some(msg) = self.host_ring_buffer.read() {
                self.host_ring_buffer.notify_read();
                let req = deserialize(&msg).unwrap();
                return Ok(req);
            }
            self.host_ring_buffer_notification.wait();
        }
    }

}

const NOW: u64 = include!("../../icecap/build/NOW");

fn icecap_runtime_init() {  
    icecap_std_external::set_panic();
    std::icecap_impl::set_now(std::time::Duration::from_secs(NOW)); // HACK
    let mut logger = Logger::default();
    logger.level = Level::Trace;
    logger.display_mode = DisplayMode::Line;
    logger.init().unwrap();
}

// HACK
mod hack {

    #[no_mangle]
    extern "C" fn fmod(x: f64, y: f64) -> f64 {
        libm::fmod(x, y)
    }

    #[no_mangle]
    extern "C" fn fmodf(x: f32, y: f32) -> f32 {
        libm::fmodf(x, y)
    }
}
