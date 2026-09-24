//! Host-side helpers shared by the server and the connector.

use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

/// `systemctl status` for `service`. A stopped unit exits non-zero; that is an
/// answer, not an error.
pub fn cmd_status(service: &str) -> io::Result<()> {
    Command::new("systemctl")
        .args(["status", service, "--no-pager"])
        .status()
        .map(drop)
}

/// Follow `service`'s journal.
pub fn cmd_logs(service: &str) -> io::Result<()> {
    Command::new("journalctl")
        .args(["-fu", service, "--no-pager"])
        .status()
        .map(drop)
}

/// Read a secret file owned by us with mode at most `max_mode`. The checks run on
/// the opened fd, so a file swapped in between check and read can't slip past.
pub fn read_secret_file(path: &Path, max_mode: u32) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let mode = metadata.permissions().mode() & 0o777;
    // Owner must be the process euid: a world-unreadable file can still be another user's.
    let euid = unsafe { libc::geteuid() };
    if mode & !max_mode != 0 || metadata.uid() != euid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "secret file {} must be owned by uid {euid} with mode at most {max_mode:03o} (has uid {}, mode {mode:03o})",
                path.display(),
                metadata.uid()
            ),
        ));
    }
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}
