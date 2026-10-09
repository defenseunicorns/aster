use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

pub struct Journal {
    pub path: PathBuf,
}
impl Journal {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "asterctl-numbered-{}-{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        aster_agent::sdk::PublicationJournal::initialize(&path, b"asterctl-test").unwrap();
        Self { path }
    }
    pub fn configure(&self, command: &mut Command) {
        command
            .arg("--journal")
            .arg(&self.path)
            .args(["--client-id", "asterctl-test"]);
    }
}
impl Drop for Journal {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
