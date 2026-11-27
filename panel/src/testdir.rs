//! Temporary directories for tests, removed when dropped.

use std::fs;
use std::path::{Path, PathBuf};

/// A new, empty directory under the system's temporary directory.
pub struct TestDir(PathBuf);

impl TestDir {
    pub fn new() -> TestDir {
        let name = format!("ocpanel-test-{}", crate::secret::token().unwrap());
        let path = std::env::temp_dir().join(name);
        fs::create_dir(&path).unwrap();
        TestDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("could not remove {}: {error}", self.0.display());
        }
    }
}
