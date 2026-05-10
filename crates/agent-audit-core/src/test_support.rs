// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_WORKSPACE_ID: AtomicUsize = AtomicUsize::new(0);

pub struct TestWorkspace {
    root: PathBuf,
}

impl TestWorkspace {
    pub fn new(name: &str) -> Self {
        let id = NEXT_WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("agent-audit-core-tests")
            .join(format!("{name}-{}-{id}", std::process::id()));

        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale test workspace");
        }
        fs::create_dir_all(&root).expect("create test workspace");

        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write_file(&self, relative_path: &str, content: &str) {
        let path = self.root.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create test file parent directory");
        }
        fs::write(path, content).expect("write test file");
    }

    pub fn create_dir(&self, relative_path: &str) {
        fs::create_dir_all(self.root.join(relative_path)).expect("create test directory");
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove test workspace");
        }
    }
}
