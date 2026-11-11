//! Where the flows write: progress to `out`, warnings and device events to
//! `err`. The tests capture both and check that no secret ever reaches them.

use std::fmt::Display;
use std::io::Write;

pub struct Term<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

impl Term<'_> {
    pub fn say(&mut self, msg: impl Display) {
        let _ = writeln!(self.out, "{msg}");
        let _ = self.out.flush();
    }

    pub fn warn(&mut self, msg: impl Display) {
        let _ = writeln!(self.err, "{msg}");
        let _ = self.err.flush();
    }
}
