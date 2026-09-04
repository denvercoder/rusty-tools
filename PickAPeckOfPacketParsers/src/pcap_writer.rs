use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Writes captured frames out in the classic (non-pcapng) libpcap file
/// format — a 24-byte global header followed by a 16-byte record header per
/// packet — so captures can be reopened directly in Wireshark.
pub struct PcapWriter {
    writer: BufWriter<File>,
}

impl PcapWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut writer = BufWriter::new(File::create(path)?);

        writer.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic number (little-endian, microsecond ts)
        writer.write_all(&2u16.to_le_bytes())?; // version major
        writer.write_all(&4u16.to_le_bytes())?; // version minor
        writer.write_all(&0i32.to_le_bytes())?; // thiszone (GMT)
        writer.write_all(&0u32.to_le_bytes())?; // sigfigs
        writer.write_all(&65535u32.to_le_bytes())?; // snaplen
        writer.write_all(&1u32.to_le_bytes())?; // network = LINKTYPE_ETHERNET

        Ok(Self { writer })
    }

    pub fn write_packet(&mut self, frame: &[u8]) -> io::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let len = frame.len() as u32;

        self.writer.write_all(&(now.as_secs() as u32).to_le_bytes())?;
        self.writer.write_all(&now.subsec_micros().to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?; // incl_len
        self.writer.write_all(&len.to_le_bytes())?; // orig_len
        self.writer.write_all(frame)?;

        // Flush per packet: capture is stopped via SIGKILL (see the
        // dashboard's Stop button), which gives no chance for a graceful
        // shutdown, so unflushed buffered packets would otherwise be lost.
        self.writer.flush()
    }
}
