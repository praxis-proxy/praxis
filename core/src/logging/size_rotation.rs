// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Size-based log file rotation.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use crate::errors::ProxyError;

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

/// Size-based file rotator used for `rotation: size:*`.
pub(crate) struct SizeRotatingWriter {
    /// Active log file path.
    path: PathBuf,
    /// Maximum active file size in bytes before rolling.
    max_bytes: u64,
    /// Total log files to retain (active plus archives).
    max_files: u32,
    /// Mutable open file and size state.
    state: Mutex<ActiveFile>,
}

/// Open file handle and byte count for the active log.
struct ActiveFile {
    /// Append handle for the active log file, if open.
    file: Option<File>,
    /// Bytes written to the active file since the last roll.
    size: u64,
}

// -----------------------------------------------------------------------------
// SizeRotatingWriter
// -----------------------------------------------------------------------------

impl SizeRotatingWriter {
    /// Open or create the log file and initialize rotation state.
    pub(crate) fn open<P: Into<PathBuf>>(path: P, max_bytes: u64, max_files: u32) -> Result<Self, ProxyError> {
        let path = path.into();
        ensure_parent_dir(&path)?;
        let file = open_append(&path)
            .map_err(|e| ProxyError::Config(format!("failed to open log file '{}': {e}", path.display())))?;
        let size = file.metadata().map_or(0, |m| m.len());
        Ok(Self {
            path,
            max_bytes,
            max_files,
            state: Mutex::new(ActiveFile { file: Some(file), size }),
        })
    }

    /// Roll the active file when it exceeds `max_bytes`.
    ///
    /// On failure after the active handle is dropped, reopens the original path
    /// so logging continues without rotation instead of leaving `file` unset.
    fn roll_locked(state: &mut ActiveFile, path: &Path, max_files: u32) -> io::Result<()> {
        let previous_size = state.size;
        if let Some(mut file) = state.file.take()
            && let Err(e) = file.flush()
        {
            state.file = Some(file);
            return Err(e);
        }

        if let Err(roll_err) = Self::perform_roll(path, max_files) {
            Self::restore_active_after_failed_roll(state, path, previous_size, roll_err)
        } else {
            state.file = Some(open_append(path)?);
            state.size = 0;
            Ok(())
        }
    }

    /// Shift archives and rename the active file to `.1`.
    fn perform_roll(path: &Path, max_files: u32) -> io::Result<()> {
        prune_and_shift(path, max_files)?;
        if max_files <= 1 {
            // Retain only the active file: discard the rolled-out content
            // instead of renaming it to `.1`, which would leave active + `.1`
            // (two files) for a configured limit of one.
            if path.exists() {
                fs::remove_file(path)?;
            }
            return Ok(());
        }
        fs::rename(path, rotated_path(path, 1))?;
        Ok(())
    }

    /// Reopen the active log after a failed roll; prefer continued logging over rotation.
    fn restore_active_after_failed_roll(
        state: &mut ActiveFile,
        path: &Path,
        fallback_size: u64,
        roll_err: io::Error,
    ) -> io::Result<()> {
        if path.exists()
            && let Ok(file) = open_append(path)
        {
            state.size = file.metadata().map_or(fallback_size, |m| m.len());
            state.file = Some(file);
            return Ok(());
        }

        let rotated = rotated_path(path, 1);
        if rotated.exists()
            && !path.exists()
            && fs::rename(&rotated, path).is_ok()
            && let Ok(file) = open_append(path)
        {
            state.size = file.metadata().map_or(fallback_size, |m| m.len());
            state.file = Some(file);
            return Ok(());
        }

        if let Ok(file) = open_append(path) {
            state.size = file.metadata().map_or(0, |m| m.len());
            state.file = Some(file);
            Ok(())
        } else {
            state.file = None;
            Err(roll_err)
        }
    }
}

// -----------------------------------------------------------------------------
// Write
// -----------------------------------------------------------------------------

impl Write for SizeRotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_e| io::Error::other("size rotation writer lock poisoned"))?;
        let file = state
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("size rotation writer file not open"))?;
        let written = file.write(buf)?;
        state.size += written as u64;
        // The bytes are already committed to the active file. If the roll
        // fails, honor io::Write by still reporting them as written rather
        // than returning Err (which a blocking caller could retry, duplicating
        // the line). size stays over the threshold, so the next write retries
        // the roll.
        if state.size >= self.max_bytes && Self::roll_locked(&mut state, &self.path, self.max_files).is_err() {
            drop(state);
            return Ok(written);
        }
        drop(state);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_e| io::Error::other("size rotation writer lock poisoned"))?;
        if let Some(file) = state.file.as_mut() {
            file.flush()?;
        }
        drop(state);
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Path helpers
// -----------------------------------------------------------------------------

/// Create parent directories for `path` when needed.
pub(crate) fn ensure_parent_dir(path: &Path) -> Result<(), ProxyError> {
    let Some(parent) = path.parent() else {
        return Err(ProxyError::Config(format!(
            "log file path '{}' has no parent directory",
            path.display()
        )));
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    fs::create_dir_all(parent)
        .map_err(|e| ProxyError::Config(format!("failed to create log directory '{}': {e}", parent.display())))
}

/// Open `path` for append, creating the file when missing.
fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Path for rotated file `path.N`.
fn rotated_path(path: &Path, index: u32) -> PathBuf {
    let file_name = path.file_name().map_or_else(
        || format!("rotated.{index}"),
        |name| format!("{}.{}", name.to_string_lossy(), index),
    );
    path.with_file_name(file_name)
}

/// Drop the oldest archive and shift `.N` → `.N+1` before rolling.
fn prune_and_shift(path: &Path, max_files: u32) -> io::Result<()> {
    if max_files <= 1 {
        if rotated_path(path, 1).exists() {
            fs::remove_file(rotated_path(path, 1))?;
        }
        return Ok(());
    }

    let archive_limit = max_files.saturating_sub(1);
    if archive_limit > 0 && rotated_path(path, archive_limit).exists() {
        fs::remove_file(rotated_path(path, archive_limit))?;
    }

    let mut index = archive_limit.saturating_sub(1);
    while index >= 1 {
        let from = rotated_path(path, index);
        if from.exists() {
            fs::rename(from, rotated_path(path, index + 1))?;
        }
        if index == 1 {
            break;
        }
        index -= 1;
    }
    Ok(())
}

/// Collect indices of existing rotated files (tests only).
#[cfg(test)]
pub(crate) fn list_rotated_indices(path: &Path) -> Vec<u32> {
    let mut indices = Vec::new();
    let mut index = 1_u32;
    while rotated_path(path, index).exists() {
        indices.push(index);
        index += 1;
    }
    indices
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, reason = "tests")]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn rolls_and_prunes_to_max_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let mut writer = SizeRotatingWriter::open(&path, 8, 3).unwrap();

        writer.write_all(b"12345678").unwrap();
        assert!(path.exists(), "active file should exist");
        assert_eq!(list_rotated_indices(&path), vec![1]);

        writer.write_all(b"abcdefgh").unwrap();
        assert_eq!(list_rotated_indices(&path), vec![1, 2]);

        writer.write_all(b"ijklmnop").unwrap();
        assert_eq!(
            list_rotated_indices(&path),
            vec![1, 2],
            "oldest archive should be pruned when max_files is 3"
        );
    }

    #[test]
    fn max_files_one_keeps_only_active() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let mut writer = SizeRotatingWriter::open(&path, 8, 1).unwrap();

        writer.write_all(b"12345678").unwrap();
        assert!(path.exists(), "active file should exist after roll");
        assert!(
            list_rotated_indices(&path).is_empty(),
            "max_files = 1 must retain only the active file, with no .1 archive"
        );

        // A second roll still leaves just the active file.
        writer.write_all(b"abcdefgh").unwrap();
        assert!(path.exists());
        assert!(list_rotated_indices(&path).is_empty());
    }

    #[test]
    fn active_file_is_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("proxy.log");
        let mut writer = SizeRotatingWriter::open(&path, 64, 7).unwrap();
        writer.write_all(b"hello").unwrap();
        writer.flush().unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("hello"));
    }

    #[test]
    fn continues_logging_when_roll_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy.log");
        let mut writer = SizeRotatingWriter::open(&path, 8, 3).unwrap();

        writer.write_all(b"12345678").unwrap();
        assert_eq!(list_rotated_indices(&path), vec![1], "first roll should succeed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mut perms = fs::metadata(dir.path()).expect("dir metadata").permissions();
            perms.set_mode(0o555);
            fs::set_permissions(dir.path(), perms).expect("make log dir read-only");
        }

        writer
            .write_all(b"abcdefgh")
            .expect("should keep writing when roll fails");
        writer.flush().expect("flush after failed roll");

        let contents = fs::read_to_string(&path).expect("active log readable");
        assert!(
            contents.contains("abcdefgh"),
            "failed roll should degrade to append-only, not stop logging"
        );
    }
}
