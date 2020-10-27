//! A minimal runtime for writing `no_std` Veracruz programs.
//!
//! Provides a global allocator (using Wee Alloc), panic-handling code, and
//! other runtime setup.  Use this crate when writing `no_std` applications for
//! Veracruz that want to use the `alloc` crate.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright notice
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

#![no_std]
#![feature(core_intrinsics)]
#![feature(lang_items)]
#![feature(alloc_error_handler)]

use core::intrinsics;
use core::panic::PanicInfo;

use wee_alloc;

#[global_allocator]
static GLOBAL_ALLOCATOR: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[alloc_error_handler]
fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
    panic!("alloc_error_handler: alloc error with layout: {:?}", layout)
}

#[panic_handler]
fn panic_handler(_info: &PanicInfo) -> ! {
    unsafe { intrinsics::abort() }
}

#[lang = "start"]
fn lang_start<T: Termination + 'static>(
    main: fn() -> T,
    _argc: isize,
    _argv: *const *const u8,
) -> isize {
    main().report() as isize
}

#[lang = "termination"]
pub trait Termination {
    fn report(self) -> i32;
}

impl Termination for () {
    #[inline]
    fn report(self) -> i32 {
        0
    }
}

impl Termination for i32 {
    #[inline]
    fn report(self) -> i32 {
        self
    }
}

impl Termination for Result<(), i32> {
    #[inline]
    fn report(self) -> i32 {
        match self {
            Ok(()) => ().report(),
            Err(err) => err.report(),
        }
    }
}
