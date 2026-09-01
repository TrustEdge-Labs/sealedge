//
// Copyright (c) 2025 TRUSTEDGE LABS LLC
// This source code is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Project: sealedge — Privacy and trust at the edge.
//

//! Secret-file custody: atomic, owner-only writes shared by the platform (the
//! JWKS signing key) and the seal CLI (device key bundles). Centralizing this
//! avoids the write-then-chmod race independently in each caller.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomically write `bytes` to `path` with owner-only (`0600`) permissions set
/// **at creation** — no world-readable window between write and a later `chmod`.
///
/// Writes to a unique sibling temp file opened with mode `0600`, `fsync`s it, then
/// renames it over the target. The unique temp name (`<path>.tmp.<pid>.<seq>`)
/// means two concurrent writers to the same target never share a temp file.
///
/// **Platform note (F6):** the all-or-nothing guarantee is Unix `rename(2)`
/// semantics — an atomic replace of the destination. On non-Unix targets the
/// bytes are still written via temp+rename, but the `0600` mode is **not** applied
/// (`OpenOptions::mode` is Unix-only); restrict access by other means there.
///
/// **Crash litter:** a crash between the temp create and the rename can leave a
/// `<path>.tmp.<pid>.<seq>` file beside the target. It is inert and safe to
/// delete; a later successful write never reuses it. (The seal CLI's `unwrap`
/// recovery leaves an analogous `<out>.seal-unwrap.<pid>.partial` on a crash.)
pub fn write_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let tmp = PathBuf::from(tmp_os);

    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;

        f.write_all(bytes)?;
        let _ = f.sync_all();
    }

    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn write_secure_writes_bytes_and_is_owner_only() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.key");
        write_secure(&path, b"top-secret").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"top-secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "secret file must be owner-only");
        }
    }

    #[test]
    fn write_secure_replaces_existing_atomically() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("k");
        write_secure(&path, b"v1").unwrap();
        write_secure(&path, b"v2-longer").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v2-longer");
        // No temp litter left behind on the success path.
        let littered = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains(".tmp."));
        assert!(!littered, "write_secure left a temp file after success");
    }
}
