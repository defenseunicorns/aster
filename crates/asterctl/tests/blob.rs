use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

const TOKEN: &str = "asterctl-test-token-00000000000000";
const BLOB_ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn cli(args: impl IntoIterator<Item = OsString>) -> Output {
    Command::new(env!("CARGO_BIN_EXE_asterctl"))
        .args(args)
        .output()
        .expect("run asterctl")
}

struct TestPath(PathBuf);

impl TestPath {
    fn new(suffix: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        Self(std::env::temp_dir().join(format!(
            "asterctl-blob-test-{}-{}-{suffix}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_dir(&self.0);
    }
}

fn source(bytes: &[u8]) -> TestPath {
    let path = TestPath::new("source");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    options
        .open(path.path())
        .and_then(|mut file| file.write_all(bytes))
        .expect("create source fixture");
    path
}

fn publish_args(path: &Path) -> Vec<OsString> {
    vec![
        "blob-publish".into(),
        "--token".into(),
        TOKEN.into(),
        "--file".into(),
        path.as_os_str().to_owned(),
        "--topic".into(),
        "imagery.maps".into(),
        "--scope".into(),
        "mission/team/alpha".into(),
        "--operation-key".into(),
        "blob-test".into(),
        "--port".into(),
        "1".into(),
    ]
}

#[test]
fn blob_help_exposes_flat_commands_and_required_paths() {
    let top = cli([OsString::from("--help")]);
    assert!(top.status.success());
    let top = String::from_utf8(top.stdout).unwrap();
    assert!(top.contains("blob-publish"));
    assert!(top.contains("blob-read"));

    let publish = cli([OsString::from("blob-publish"), OsString::from("--help")]);
    assert!(publish.status.success());
    let publish = String::from_utf8(publish.stdout).unwrap();
    for option in [
        "--file",
        "--topic",
        "--scope",
        "--operation-key",
        "--ttl-ms",
    ] {
        assert!(publish.contains(option), "missing {option}: {publish}");
    }

    let read = cli([OsString::from("blob-read"), OsString::from("--help")]);
    assert!(read.status.success());
    let read = String::from_utf8(read.stdout).unwrap();
    for option in ["--id", "--topic", "--scope", "--output"] {
        assert!(read.contains(option), "missing {option}: {read}");
    }
}

#[test]
fn blob_publish_ttl_accepts_positive_u64_and_rejects_other_spellings() {
    let input = source(b"blob");
    for ttl in ["1", "18446744073709551615"] {
        let mut args = publish_args(input.path());
        args.extend(["--ttl-ms".into(), ttl.into()]);
        let output = cli(args);
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("PublishBlob"), "{ttl}: {stderr}");
        assert!(!stderr.contains("TTL must be"), "{ttl}: {stderr}");
    }
    for ttl in ["0", "-1", "18446744073709551616", "+1", "1.0"] {
        let mut args = publish_args(input.path());
        args.extend(["--ttl-ms".into(), ttl.into()]);
        let output = cli(args);
        assert_eq!(output.status.code(), Some(2), "{ttl}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("TTL must be"), "{ttl}: {stderr}");
    }
}

#[test]
fn blob_publish_requires_a_regular_nonempty_source() {
    let empty = source(&[]);
    let output = cli(publish_args(empty.path()));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("source file must not be empty")
    );

    let directory = TestPath::new("directory");
    fs::create_dir(directory.path()).unwrap();
    let output = cli(publish_args(directory.path()));
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("source must be a regular file")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn blob_publish_rejects_a_writerless_fifo_without_blocking_preflight() {
    let fifo = TestPath::new("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(fifo.path())
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new("timeout")
        .arg("1")
        .arg(env!("CARGO_BIN_EXE_asterctl"))
        .args(publish_args(fifo.path()))
        .output()
        .expect("run asterctl with timeout");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("source must be a regular file")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn blob_read_rejects_an_existing_output_without_clobbering_it() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = TestPath::new("existing-output-directory");
    fs::create_dir(directory.path()).unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let output_path = directory.path().join("destination");
    fs::write(&output_path, b"keep me").unwrap();
    let output = cli([
        OsString::from("blob-read"),
        "--token".into(),
        TOKEN.into(),
        "--id".into(),
        BLOB_ID.into(),
        "--topic".into(),
        "imagery.maps".into(),
        "--scope".into(),
        "mission/team/alpha".into(),
        "--output".into(),
        output_path.as_os_str().to_owned(),
        "--port".into(),
        "1".into(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&output_path).unwrap(), b"keep me");
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("output path already exists")
    );
    fs::remove_file(output_path).unwrap();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn blob_read_rejects_unsupported_platforms_before_contact_or_output_creation() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let destination = TestPath::new("unsupported-read");
    let output = cli([
        OsString::from("blob-read"),
        "--token".into(),
        TOKEN.into(),
        "--id".into(),
        BLOB_ID.into(),
        "--topic".into(),
        "imagery.maps".into(),
        "--scope".into(),
        "mission/team/alpha".into(),
        "--output".into(),
        destination.path().as_os_str().to_owned(),
        "--port".into(),
        listener.local_addr().unwrap().port().to_string().into(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("blob-read output is unsupported on this platform")
    );
    assert!(!destination.path().exists());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn blob_commands_require_every_semantic_and_path_argument() {
    for args in [
        vec!["blob-publish", "--token", TOKEN],
        vec!["blob-read", "--token", TOKEN],
        vec![
            "blob-read",
            "--token",
            TOKEN,
            "--id",
            BLOB_ID,
            "--topic",
            "imagery.maps",
            "--scope",
            "mission/team/alpha",
        ],
    ] {
        let output = cli(args.into_iter().map(OsString::from));
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("required")
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn blob_commands_preserve_non_utf8_native_paths() {
    use std::os::unix::ffi::OsStringExt as _;

    let path = TestPath::new("native-parent");
    fs::create_dir(path.path()).unwrap();
    let native = path
        .path()
        .join(OsString::from_vec(b"blob-\xff.bin".to_vec()));
    fs::write(&native, b"blob").unwrap();
    let output = cli(publish_args(&native));
    let _ = fs::remove_file(native);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("PublishBlob"), "{stderr}");
    assert!(!stderr.contains("UTF-8"), "{stderr}");

    let native_output = path
        .path()
        .join(OsString::from_vec(b"output-\xff.bin".to_vec()));
    fs::write(&native_output, b"keep me").unwrap();
    let output = cli([
        OsString::from("blob-read"),
        "--token".into(),
        TOKEN.into(),
        "--id".into(),
        BLOB_ID.into(),
        "--topic".into(),
        "imagery.maps".into(),
        "--scope".into(),
        "mission/team/alpha".into(),
        "--output".into(),
        native_output.as_os_str().to_owned(),
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&native_output).unwrap(), b"keep me");
    fs::remove_file(native_output).unwrap();
    assert!(!String::from_utf8(output.stderr).unwrap().contains("UTF-8"));
}
