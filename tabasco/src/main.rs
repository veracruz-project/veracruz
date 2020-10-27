//! Tabasco
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[macro_use]
extern crate diesel;

mod attestation;
mod orm;
mod server;
#[cfg(test)]
mod test;
use actix_rt::System;
use std::{
    sync::{mpsc, Once},
    thread, time,
};

static SETUP: Once = Once::new();

fn main() {
    std::env::set_var("RUST_LOG", "actix_web=info,actix_server=trace");
    env_logger::init();

    let (tx, rx) = mpsc::channel();

    SETUP.call_once(|| {
        thread::spawn(move || {
            let mut sys = System::new("test");
            let server = server::server("127.0.0.1:3016".to_string()).unwrap();
            let _ = tx.send(server.clone());
            sys.block_on(server);
            println!("end of the daemon thread");
        });
    });
    let srv = rx.recv().unwrap();
    thread::sleep(time::Duration::from_secs(10));
    System::new("").block_on(srv.stop(true));
    println!("end of the main thread");
}
