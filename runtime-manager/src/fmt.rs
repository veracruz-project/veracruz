use core::fmt;

use icecap_core::ring_buffer::*;

#[macro_export]
macro_rules! out {
    ($dst:expr, $($arg:tt)*) => ($crate::fmt::Writer($dst).write_fmt(format_args!($($arg)*)).unwrap());
}

pub(crate) struct Writer<'a>(pub &'a mut BufferedRingBuffer);
    
impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.tx(s.as_bytes());
        Ok(())
    }
}
