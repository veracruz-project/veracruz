//! An implementation of the WASI API for Execution Engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(unused_variables)] // while most of the functions are unimplemented

use super::common::MemoryHandler;
use crate::fs::FileSystemResult;
use std::fmt;

pub struct Strace {}

impl Strace {
    pub fn func(enabled: bool, name: &str) -> Self {
        // NOT YET IMPLEMENTED
        Strace {}
    }

    pub fn arg_buffer<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32, len: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_dec<T: fmt::Display>(&mut self, n: T) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_dots(&mut self) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_dirents<T: MemoryHandler>(
        &mut self,
        _mem: &mut T,
        _buf_ptr: u32,
        _buf_len: u32,
        _result_ptr: u32,
    ) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_events<T: MemoryHandler>(&mut self, _mem: &mut T, _events: u32, _size: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_fdstat<T: MemoryHandler>(&mut self, _mem: &mut T, _adr: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_filestat<T: MemoryHandler>(&mut self, _mem: &mut T, _adr: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_hex<T: fmt::LowerHex>(&mut self, n: T) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_iovec<T: MemoryHandler>(
        &mut self,
        res: FileSystemResult<()>,
        memory_ref: &mut T,
        base: u32,
        count: u32,
        address: u32,
    ) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_p_u16_hex<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_p_u32<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_p_u64<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_path<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32, len: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_prestat_out<T: MemoryHandler>(
        &mut self,
        res: FileSystemResult<()>,
        mem: &mut T,
        adr: u32,
    ) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_rights(&mut self, rights: u64) {
        // NOT YET IMPLEMENTED
    }

    pub fn arg_subscriptions<T: MemoryHandler>(&mut self, _mem: &mut T, _expr: u32, _size: u32) {
        // NOT YET IMPLEMENTED
    }

    pub fn result(&mut self, result: FileSystemResult<()>) -> FileSystemResult<()> {
        // NOT YET IMPLEMENTED
        result
    }
}
