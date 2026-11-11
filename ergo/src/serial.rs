//! The device's USB serial console as a line-oriented [`Console`], so the
//! commission flow runs against a scripted fake in the tests.
//!
//! [`SerialConsole`] reads on a thread of its own and hands complete lines to
//! the async side over a channel, so a read never blocks the runtime and
//! Ctrl-C is noticed at once.

use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use device_core::console::MAX_LINE;
use tokio::sync::mpsc;

/// One line in, one line out.
#[allow(async_fn_in_trait)]
pub trait Console {
    /// Sends `line` followed by `\n`.
    fn send_line(&mut self, line: &str) -> Result<()>;
    /// The next complete line (without its terminator), or `None` if none
    /// arrived within `timeout`.
    async fn read_line(&mut self, timeout: Duration) -> Result<Option<String>>;
}

pub struct SerialConsole {
    writer: Box<dyn serialport::SerialPort>,
    lines: mpsc::UnboundedReceiver<Result<String, String>>,
}

impl SerialConsole {
    pub fn open(path: &str, baud: u32) -> Result<Self> {
        let writer = serialport::new(path, baud)
            // Writes: a claim key in base64 is ~2.3 KB, 0.2 s at 115200.
            .timeout(Duration::from_secs(5))
            .open()
            .with_context(|| format!("opening serial port {path}"))?;
        let mut reader = writer
            .try_clone()
            .with_context(|| format!("cloning serial port {path}"))?;
        reader.set_timeout(Duration::from_millis(100))?;
        let (tx, lines) = mpsc::unbounded_channel();
        std::thread::spawn(move || read_lines(reader.as_mut(), &tx));
        Ok(Self { writer, lines })
    }
}

/// Splits the byte stream into lines until the receiver goes away or the port
/// fails. Over-long lines (a log dump) are dropped, not buffered forever.
fn read_lines(port: &mut dyn Read, tx: &mpsc::UnboundedSender<Result<String, String>>) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 512];
    let mut overflow = false;
    loop {
        match port.read(&mut buf) {
            // A timeout is an error (below); zero bytes means the device went
            // away (USB unplugged, or re-enumerating as it restarts).
            Ok(0) => {
                let _ = tx.send(Err("the serial port closed".into()));
                return;
            }
            Ok(n) => {
                for &b in &buf[..n] {
                    if b == b'\n' {
                        if !overflow {
                            let line = String::from_utf8_lossy(&pending)
                                .trim_end_matches('\r')
                                .to_string();
                            if tx.send(Ok(line)).is_err() {
                                return;
                            }
                        }
                        pending.clear();
                        overflow = false;
                    } else if pending.len() < 2 * MAX_LINE {
                        pending.push(b);
                    } else {
                        overflow = true;
                    }
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::Interrupted) => {
                if tx.is_closed() {
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(format!("serial port read failed: {e}")));
                return;
            }
        }
    }
}

impl Console for SerialConsole {
    fn send_line(&mut self, line: &str) -> Result<()> {
        self.writer
            .write_all(line.as_bytes())
            .and_then(|()| self.writer.write_all(b"\n"))
            .and_then(|()| self.writer.flush())
            .context("serial port write failed")
    }

    async fn read_line(&mut self, timeout: Duration) -> Result<Option<String>> {
        match tokio::time::timeout(timeout, self.lines.recv()).await {
            Err(_elapsed) => Ok(None),
            Ok(Some(Ok(line))) => Ok(Some(line)),
            Ok(Some(Err(e))) => Err(anyhow!(e)),
            Ok(None) => Err(anyhow!("the serial port closed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_become_lines() {
        let long = "x".repeat(3 * MAX_LINE);
        let input = format!("boot\r\nPLATFORM OK SET wifi_ssid\n{long}\npartial");
        let (tx, mut rx) = mpsc::unbounded_channel();
        read_lines(&mut input.as_bytes(), &tx);
        let mut got = Vec::new();
        while let Ok(item) = rx.try_recv() {
            got.push(item);
        }
        assert_eq!(
            got,
            [
                Ok("boot".to_string()),
                Ok("PLATFORM OK SET wifi_ssid".to_string()),
                Err("the serial port closed".to_string()),
            ],
            "the over-long line and the unterminated tail are dropped"
        );
    }
}
