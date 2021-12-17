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

use super::common::MemoryHandler;
use crate::fs::FileSystemResult;
use std::fmt;

enum TraceState {
    Func,
    Args,
    Result,
}

pub struct Strace {
    enabled: bool,
    state: TraceState,
}

// Convert a vector of bytes into a printable ASCII string.
// The string may contain readable text, which is useful to display,
// but it may also contain binary data, so we cannot decode it as UTF-8.
fn strace_string(bytes: &[u8], max: usize) -> String {
    let mut res = String::from("\"");
    let n = if bytes.len() > max { max } else { bytes.len() };
    for i in 0..n {
        if 0x20 <= bytes[i] && bytes[i] < 0x7f {
            if bytes[i] == b'\\' || bytes[i] == b'"' {
                res.push_str("\\");
            }
            res.push_str(&String::from_utf8_lossy(&bytes[i..i + 1].to_vec()))
        } else if bytes[i] == 9 {
            res.push_str("\\t")
        } else if bytes[i] == 10 {
            res.push_str("\\n")
        } else if i + 1 < n && b'0' <= bytes[i + 1] && bytes[i + 1] <= b'9' {
            // The following character is a digit, so use three octal digits.
            res.push_str(&format!("\\{:03o}", bytes[i]))
        } else {
            res.push_str(&format!("\\{:o}", bytes[i]))
        }
    }
    res.push_str("\"");
    if bytes.len() > max {
        res.push_str("...")
    }
    res
}

impl Strace {
    pub fn func(enabled: bool, name: &str) -> Self {
        if enabled {
            eprint!("{}(", name)
        };
        Strace {
            enabled,
            state: TraceState::Func,
        }
    }

    fn arg(&mut self) -> bool {
        if !self.enabled {
            return true;
        }
        match self.state {
            TraceState::Func => self.state = TraceState::Args,
            TraceState::Args => {
                eprint!(", ");
            }
            TraceState::Result => eprint!("\nUnexpected strace arg: "),
        }
        false
    }

    pub fn arg_buffer<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32, len: u32) {
        if self.arg() {
            return;
        }
        let mut bytes = vec![0u8; len as usize];
        match mem.read_buffer(adr, &mut bytes) {
            Ok(()) => eprint!("{}", strace_string(&bytes, 32)),
            Err(_) => eprint!("BAD_MEM_REF"),
        }
    }

    pub fn arg_dec<T: fmt::Display>(&mut self, n: T) {
        if self.arg() {
            return;
        }
        eprint!("{}", n)
    }

    pub fn arg_dots(&mut self) {
        if self.arg() {
            return;
        }
        eprint!("...")
    }

    pub fn arg_dirents<T: MemoryHandler>(
        &mut self,
        _mem: &mut T,
        _buf_ptr: u32,
        _buf_len: u32,
        _result_ptr: u32,
    ) {
        if self.arg() {
            return;
        }
        // NOT YET IMPLEMENTED
        eprint!("DIRENTS")
    }

    pub fn arg_events<T: MemoryHandler>(&mut self, _mem: &mut T, _events: u32, _size: u32) {
        if self.arg() {
            return;
        }
        // NOT YET IMPLEMENTED
        eprint!("EVENTS")
    }

    pub fn arg_fdstat<T: MemoryHandler>(&mut self, _mem: &mut T, _adr: u32) {
        if self.arg() {
            return;
        }
        // NOT YET IMPLEMENTED
        eprint!("FDSTAT")
    }

    pub fn arg_filestat<T: MemoryHandler>(&mut self, _mem: &mut T, _adr: u32) {
        if self.arg() {
            return;
        }
        // NOT YET IMPLEMENTED
        eprint!("FILESTAT")
    }

    pub fn arg_hex<T: fmt::LowerHex>(&mut self, n: T) {
        if self.arg() {
            return;
        }
        eprint!("0x{:x}", n)
    }

    pub fn arg_iovec<T: MemoryHandler>(
        &mut self,
        res: FileSystemResult<()>,
        memory_ref: &mut T,
        base: u32,
        count: u32,
        address: u32,
    ) {
        if self.arg() {
            return;
        }
        if !res.is_ok() {
            eprint!("_");
            return;
        }
        if let Ok(len) = memory_ref.read_u32(address) {
            // This inefficiently copies everything, but it's only used for tracing.
            if let Ok(bufs) = memory_ref.unpack_iovec(base, count) {
                let mut buf: Vec<u8> = Vec::new();
                for b in bufs.as_ref() {
                    buf.extend(b.as_ref())
                }
                buf.truncate(len as usize);
                eprint!("{}", strace_string(&buf, 32))
            } else {
                eprint!("BAD_IOVEC")
            }
        } else {
            eprint!("BAD_IOVEC_LEN") // This will probably never happen.
        }
    }

    pub fn arg_p_u16_hex<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        if self.arg() {
            return;
        }
        match mem.read_u16(adr) {
            Ok(x) => eprint!("0x{:x}", x),
            Err(_) => eprint!("BAD_MEM_REF"),
        }
    }

    pub fn arg_p_u32<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        if self.arg() {
            return;
        }
        match mem.read_u32(adr) {
            Ok(x) => eprint!("{}", x),
            Err(_) => eprint!("BAD_MEM_REF"),
        }
    }

    pub fn arg_p_u64<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        if self.arg() {
            return;
        }
        match mem.read_u64(adr) {
            Ok(x) => eprint!("{}", x),
            Err(_) => eprint!("BAD_MEM_REF"),
        }
    }

    pub fn arg_path<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32, len: u32) {
        if self.arg() {
            return;
        }
        let mut bytes = vec![0u8; len as usize];
        match mem.read_buffer(adr, &mut bytes) {
            Ok(()) => eprint!("{}", strace_string(&bytes, 1024)),
            Err(_) => eprint!("BAD_MEM_REF"),
        }
    }

    pub fn arg_prestat_out<T: MemoryHandler>(
        &mut self,
        res: FileSystemResult<()>,
        mem: &mut T,
        adr: u32,
    ) {
        if self.arg() {
            return;
        }
        if res.is_ok() {
            match mem.read_u64(adr) {
                Ok(x) => {
                    if x & 0xffffffff == 0 {
                        eprint!("{{len={}}}", x >> 32)
                    } else {
                        eprint!("BAD_PRESTAT");
                    }
                }
                Err(_) => eprint!("BAD_MEM_REF"),
            }
        } else {
            eprint!("_")
        }
    }

    pub fn arg_rights(&mut self, rights: u64) {
        if self.arg() {
            return;
        }
        eprint!("0x{:x}", rights)
    }

    pub fn arg_subscriptions<T: MemoryHandler>(&mut self, _mem: &mut T, _expr: u32, _size: u32) {
        if self.arg() {
            return;
        }
        // NOT YET IMPLEMENTED
        eprint!("SUBSCRIPTIONS")
    }

    pub fn result(&mut self, result: FileSystemResult<()>) -> FileSystemResult<()> {
        if !self.enabled {
            return result;
        }
        match self.state {
            TraceState::Result => eprint!("\nUnexpected strace result: "),
            _ => self.state = TraceState::Result,
        }
        match result {
            Ok(()) => eprintln!(") = Success"),
            Err(x) => eprintln!(") = {:?}", x),
        };
        result
    }
}
