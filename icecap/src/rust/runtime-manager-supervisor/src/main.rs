//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![no_std]
#![no_main]
#![feature(format_args_nl)]

use serde::{Deserialize, Serialize};

use icecap_std::prelude::*;
use icecap_std::logger::{DisplayMode, Level, Logger};
use icecap_std::rpc_sel4::RPCClient;
use icecap_std::runtime as icecap_runtime;
use icecap_start_generic::declare_generic_main;

declare_generic_main!(main);

const LOG_LEVEL: Level = Level::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    ep: Endpoint,
    runtime_manager_pgd: PGD,
    runtime_manager_tcb: TCB,
    request_badge: Badge,
    fault_badge: Badge,
    mmap_base: usize,
    pool: Pool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pool {
    large_pages: Vec<LargePage>,
    hack_large_pages: Vec<LargePage>,
}

fn init_logging() {
    let mut logger = Logger::default();
    logger.level = LOG_LEVEL;
    logger.display_mode = DisplayMode::Line;
    logger.write = |s| debug_println!("{}", s);
    logger.init().unwrap();
}

fn main(config: Config) -> Fallible<()> {
    let mut config = config; // HACK

    init_logging();
    // debug_println!("{:x?}", config);

    for cap in &config.pool.hack_large_pages {
        cap.unmap()?;
    }

    // test
    let page = config.pool.large_pages.pop().unwrap();
    let vaddr = config.mmap_base;
    page.map(config.runtime_manager_pgd, vaddr, CapRights::read_write(), VMAttributes::default())?;

    debug_println!("supervisor main loop");
    loop {
        let (info, badge) = config.ep.recv();
        if badge == config.request_badge {
        } else if badge == config.fault_badge {
        } else {
            panic!()
        }
    }
    Ok(())
}
