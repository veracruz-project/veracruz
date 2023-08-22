//! An implementation of the WASI API for Execution Engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

//use super::common::MemoryHandler;
//use log::info;

///// How many characters to display from a string or memory buffer.
//const BUFFER_DISPLAY_LEN: usize = 32;

///// State of strace structure.
//enum TraceState {
    ///// Initial state: we have only seen the function name.
    //Func,
    ///// We have seen one or more arguments.
    //Args,
    ///// We have seen the result of the function all.
    //Done,
//}

//pub struct Strace {
    //enabled: bool,
    //state: TraceState,
//}

///// Convert a vector of bytes into a printable ASCII string.
///// The string may contain readable text, which is useful to display,
///// but it may also contain binary data, so we cannot decode it as UTF-8.
//fn strace_string(bytes: &[u8], max: usize) -> String {
    //let mut res = String::from("\"");
    //let n = if bytes.len() > max { max } else { bytes.len() };
    //for i in 0..n {
        //if 0x20 <= bytes[i] && bytes[i] < 0x7f {
            //if bytes[i] == b'\\' || bytes[i] == b'"' {
                //res.push_str("\\");
            //}
            //res.push_str(&String::from_utf8_lossy(&bytes[i..i + 1].to_vec()))
        //} else if bytes[i] == 9 {
            //res.push_str("\\t")
        //} else if bytes[i] == 10 {
            //res.push_str("\\n")
        //} else if i + 1 < n && b'0' <= bytes[i + 1] && bytes[i + 1] <= b'9' {
            //// The following character is a digit, so use three octal digits.
            //res.push_str(&format!("\\{:03o}", bytes[i]))
        //} else {
            //res.push_str(&format!("\\{:o}", bytes[i]))
        //}
    //}
    //res.push_str("\"");
    //if bytes.len() > max {
        //res.push_str("...")
    //}
    //res
//}

//impl Strace {
    ///// Start generating strace output, given function name.
    //pub fn func(enabled: bool, name: &str) -> Self {
        //if enabled {
            //info!("{}(", name)
        //};
        //Strace {
            //enabled,
            //state: TraceState::Func,
        //}
    //}

    ///// Common code for handling arguments: prints comma as required.
    //fn arg_print_comma(&mut self) {
        //match self.state {
            //TraceState::Func => self.state = TraceState::Args,
            //TraceState::Args => {
                //info!(", ");
            //}
            //TraceState::Done => info!("\nUnexpected strace arg: "),
        //}
    //}

    ///// Handle argument that is a memory buffer.
    //pub fn arg_buffer<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32, len: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //let mut bytes = vec![0u8; len as usize];
        //match mem.read_buffer(adr, &mut bytes) {
            //Ok(()) => info!("{}", strace_string(&bytes, BUFFER_DISPLAY_LEN)),
            //Err(_) => info!("BAD_MEM_REF"),
        //}
    //}

    ///// Handle argument as decimal value.
    //pub fn arg_dec<T: fmt::Display>(&mut self, n: T) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //info!("{}", n)
    //}

    ///// Print ellipsis ("...") for argument that we do not display.
    //pub fn arg_dots(&mut self) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //info!("...")
    //}

    ///// Handle argument that is a directory entry.
    //pub fn arg_dirents<T: MemoryHandler>(
        //&mut self,
        //_mem: &mut T,
        //_buf_ptr: u32,
        //_buf_len: u32,
        //_result_ptr: u32,
    //) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //// NOT YET IMPLEMENTED
        //info!("DIRENTS")
    //}

    ///// Handle argument that represents events (for poll_oneoff).
    //pub fn arg_events<T: MemoryHandler>(&mut self, _mem: &mut T, _events: u32, _size: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //// NOT YET IMPLEMENTED
        //info!("EVENTS")
    //}

    ///// Handle argument fdstat (for fd_fdstat_get).
    //pub fn arg_fdstat<T: MemoryHandler>(&mut self, _mem: &mut T, _adr: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //// NOT YET IMPLEMENTED
        //info!("FDSTAT")
    //}

    ///// Handle argument filestat.
    //pub fn arg_filestat<T: MemoryHandler>(&mut self, _mem: &mut T, _adr: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //// NOT YET IMPLEMENTED
        //info!("FILESTAT")
    //}

    ///// Handle argument as hexadecimal value.
    //pub fn arg_hex<T: fmt::LowerHex>(&mut self, n: T) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //info!("0x{:x}", n)
    //}

    ///// Handle argument that is an iovec.
    //pub fn arg_iovec<T: MemoryHandler>(
        //&mut self,
        //res: FileSystemResult<()>,
        //memory_ref: &mut T,
        //base: u32,
        //count: u32,
        //address: u32,
    //) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //if !res.is_ok() {
            //info!("_");
            //return;
        //}
        //if let Ok(len) = memory_ref.read_u32(address) {
            //// This inefficiently copies everything, but it's only used for tracing.
            //if let Ok(bufs) = memory_ref.unpack_iovec(base, count) {
                //let mut buf: Vec<u8> = Vec::new();
                //for b in bufs.as_ref() {
                    //buf.extend(b.as_ref())
                //}
                //buf.truncate(len as usize);
                //info!("{}", strace_string(&buf, BUFFER_DISPLAY_LEN))
            //} else {
                //info!("BAD_IOVEC")
            //}
        //} else {
            //info!("BAD_IOVEC_LEN") // This will probably never happen.
        //}
    //}

    ///// Handle argument that is a pointer to u16, displayed as hex.
    //pub fn arg_p_u16_hex<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //match mem.read_u16(adr) {
            //Ok(x) => info!("0x{:x}", x),
            //Err(_) => info!("BAD_MEM_REF"),
        //}
    //}

    ///// Handle argument that is a pointer to u32, displayed as hex.
    //pub fn arg_p_u32<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //match mem.read_u32(adr) {
            //Ok(x) => info!("{}", x),
            //Err(_) => info!("BAD_MEM_REF"),
        //}
    //}

    ///// Handle argument that is a pointer to u64, displayed as hex.
    //pub fn arg_p_u64<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //match mem.read_u64(adr) {
            //Ok(x) => info!("{}", x),
            //Err(_) => info!("BAD_MEM_REF"),
        //}
    //}

    ///// Handle argument that is a file path.
    //pub fn arg_path<T: MemoryHandler>(&mut self, mem: &mut T, adr: u32, len: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //let mut bytes = vec![0u8; len as usize];
        //match mem.read_buffer(adr, &mut bytes) {
            //Ok(()) => info!("{}", strace_string(&bytes, 1024)),
            //Err(_) => info!("BAD_MEM_REF"),
        //}
    //}

    ///// Handle argument that is prestat (for fd_prestat_get).
    //pub fn arg_prestat_out<T: MemoryHandler>(
        //&mut self,
        //res: FileSystemResult<()>,
        //mem: &mut T,
        //adr: u32,
    //) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //if res.is_ok() {
            //match mem.read_u64(adr) {
                //Ok(x) => {
                    //if x & 0xffffffff == 0 {
                        //info!("{{len={}}}", x >> 32)
                    //} else {
                        //info!("BAD_PRESTAT");
                    //}
                //}
                //Err(_) => info!("BAD_MEM_REF"),
            //}
        //} else {
            //info!("_")
        //}
    //}

    ///// Handle argument that represents access rights (for path_open).
    //pub fn arg_rights(&mut self, rights: u64) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //info!("0x{:x}", rights)
    //}

    ///// Handle argument subscriptions (for poll_oneoff).
    //pub fn arg_subscriptions<T: MemoryHandler>(&mut self, _mem: &mut T, _expr: u32, _size: u32) {
        //if !self.enabled {
            //return;
        //}
        //self.arg_print_comma();
        //// NOT YET IMPLEMENTED
        //info!("SUBSCRIPTIONS")
    //}

    ///// Handle results returned from function; this function is called last.
    //pub fn result(&mut self, result: FileSystemResult<()>) -> FileSystemResult<()> {
        //if !self.enabled {
            //return result;
        //}
        //match self.state {
            //TraceState::Done => info!("\nUnexpected strace result: "),
            //_ => self.state = TraceState::Done,
        //}
        //match result {
            //Ok(()) => info!(") = Success"),
            //Err(x) => info!(") = {:?}", x),
        //};
        //result
    //}
//}
