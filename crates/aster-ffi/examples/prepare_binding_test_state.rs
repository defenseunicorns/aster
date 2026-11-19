//! Generates a disposable three-head Record conflict for real foreign bindings.
#[path = "../tests/support/mod.rs"]
mod support;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .ok_or("pass an empty testdata directory")?;
    if path.file_name().is_none_or(|n| n != "testdata") || path.exists() {
        return Err("fixture requires a new directory named testdata".into());
    }
    support::prepare(&path)
}
