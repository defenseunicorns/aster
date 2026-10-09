#![cfg(target_os = "linux")]

use aster_compose_credentials::{
    ComposeActivation, ComposeCredentialError, ComposeCredentialReason,
};
use std::{
    fs,
    os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[path = "../src/mountinfo.rs"]
mod mountinfo;
#[path = "../src/secret_file.rs"]
mod secret_file;

const TARGET: &[u8] = b"/run/secrets/aster-provisioning-bundle";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-compose-secret-boundary-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create unique test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove owned test directory");
    }
}

fn mountinfo(target: &[u8], options: &[u8], super_options: &[u8]) -> Vec<u8> {
    let mut line = b"31 24 0:28 / ".to_vec();
    line.extend_from_slice(target);
    line.push(b' ');
    line.extend_from_slice(options);
    line.extend_from_slice(b" - tmpfs tmpfs ");
    line.extend_from_slice(super_options);
    line.push(b'\n');
    line
}

fn write_secret(root: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).expect("write fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
    path
}

fn read(
    root: &Path,
    name: &str,
    mountinfo_bytes: &[u8],
    effective_uid: u32,
    max_bytes: usize,
    fault: secret_file::ReadFault,
) -> Result<Vec<u8>, ComposeCredentialReason> {
    secret_file::read_secret_for_test(
        root,
        name,
        TARGET,
        mountinfo_bytes,
        effective_uid,
        max_bytes,
        fault,
    )
    .map(|bytes| bytes.to_vec())
    .map_err(|error| error.reason())
}

#[test]
fn regular_owner_only_files_are_read_with_exact_bounds() {
    // Break caught: rejecting the supported 0400/0600 file presentation, or
    // reading beyond the caller's exact bound, breaks valid Compose startup.
    let uid = rustix::process::geteuid().as_raw();
    assert_ne!(uid, 0, "boundary tests require a non-root test runner");
    let mountinfo = mountinfo(TARGET, b"ro,nosuid,nodev,noexec", b"rw");
    for mode in [0o400, 0o600] {
        let root = TempDirectory::new();
        write_secret(root.path(), "credential", b"canonical", mode);
        assert_eq!(
            read(
                root.path(),
                "credential",
                &mountinfo,
                uid,
                b"canonical".len(),
                secret_file::ReadFault::None,
            ),
            Ok(b"canonical".to_vec()),
            "mode {mode:o}"
        );
    }
}

#[test]
fn symlinks_fifo_directory_and_hard_link_fail_closed() {
    // Break caught: following a final/parent symlink, blocking on a FIFO, or
    // accepting a non-regular or multiply-linked inode escapes file custody.
    let uid = rustix::process::geteuid().as_raw();
    let mountinfo = mountinfo(TARGET, b"ro", b"rw");

    let root = TempDirectory::new();
    let target = write_secret(root.path(), "target", b"secret", 0o400);
    std::os::unix::fs::symlink(&target, root.path().join("final-link")).expect("final symlink");
    assert_eq!(
        read(
            root.path(),
            "final-link",
            &mountinfo,
            uid,
            64,
            secret_file::ReadFault::None
        ),
        Err(ComposeCredentialReason::InvalidMountBoundary)
    );

    let parent = TempDirectory::new();
    std::os::unix::fs::symlink(root.path(), parent.path().join("linked-root"))
        .expect("parent symlink");
    assert_eq!(
        read(
            &parent.path().join("linked-root"),
            "target",
            &mountinfo,
            uid,
            64,
            secret_file::ReadFault::None,
        ),
        Err(ComposeCredentialReason::InvalidMountBoundary)
    );

    let objects = TempDirectory::new();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        objects.path().join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o400),
        0,
    )
    .expect("create fifo");
    assert_eq!(
        read(
            objects.path(),
            "fifo",
            &mountinfo,
            uid,
            64,
            secret_file::ReadFault::None
        ),
        Err(ComposeCredentialReason::NotRegular)
    );
    fs::create_dir(objects.path().join("directory")).expect("create directory fixture");
    assert_eq!(
        read(
            objects.path(),
            "directory",
            &mountinfo,
            uid,
            64,
            secret_file::ReadFault::None
        ),
        Err(ComposeCredentialReason::NotRegular)
    );
    let first = write_secret(objects.path(), "first", b"secret", 0o400);
    fs::hard_link(&first, objects.path().join("second")).expect("hard link fixture");
    assert_eq!(
        read(
            objects.path(),
            "first",
            &mountinfo,
            uid,
            64,
            secret_file::ReadFault::None
        ),
        Err(ComposeCredentialReason::LinkCount)
    );
}

#[test]
fn owner_root_mode_size_truncation_and_change_are_rejected() {
    // Break caught: accepting root/other ownership, broad modes, oversized
    // input, or a racing inode permits mutable or over-privileged secrets.
    let uid = rustix::process::geteuid().as_raw();
    let mountinfo = mountinfo(TARGET, b"ro", b"rw");

    let wrong_owner = TempDirectory::new();
    write_secret(wrong_owner.path(), "credential", b"secret", 0o400);
    assert_eq!(
        read(
            wrong_owner.path(),
            "credential",
            &mountinfo,
            uid + 1,
            64,
            secret_file::ReadFault::None
        ),
        Err(ComposeCredentialReason::Ownership)
    );
    assert_eq!(
        read(
            wrong_owner.path(),
            "credential",
            &mountinfo,
            0,
            64,
            secret_file::ReadFault::None
        ),
        Err(ComposeCredentialReason::Ownership)
    );

    for mode in [0o000, 0o200, 0o440, 0o640, 0o700] {
        let root = TempDirectory::new();
        write_secret(root.path(), "credential", b"secret", mode);
        assert_eq!(
            read(
                root.path(),
                "credential",
                &mountinfo,
                uid,
                64,
                secret_file::ReadFault::None
            ),
            Err(ComposeCredentialReason::Permissions),
            "mode {mode:o}"
        );
    }

    let oversized = TempDirectory::new();
    write_secret(oversized.path(), "credential", b"too-long", 0o400);
    assert_eq!(
        read(
            oversized.path(),
            "credential",
            &mountinfo,
            uid,
            3,
            secret_file::ReadFault::None
        ),
        Err(ComposeCredentialReason::TooLarge)
    );

    let changed = TempDirectory::new();
    write_secret(changed.path(), "credential", b"changes", 0o600);
    assert_eq!(
        read(
            changed.path(),
            "credential",
            &mountinfo,
            uid,
            64,
            secret_file::ReadFault::Truncate
        ),
        Err(ComposeCredentialReason::Changed)
    );

    let truncated = TempDirectory::new();
    write_secret(truncated.path(), "credential", b"ASTRCSAC", 0o400);
    let bytes = read(
        truncated.path(),
        "credential",
        &mountinfo,
        uid,
        1024,
        secret_file::ReadFault::None,
    )
    .expect("secure bounded read");
    assert_eq!(
        ComposeActivation::from_bytes(&bytes)
            .expect_err("truncated activation")
            .reason(),
        ComposeCredentialReason::InvalidActivation
    );
}

#[test]
fn mountinfo_decodes_defined_escapes_and_requires_one_exact_read_only_target() {
    // Break caught: lexical prefix matching, wrong-field ro, duplicate mounts,
    // or incomplete escape decoding can misclassify a writable secret mount.
    let escaped = b"/run/secrets/a\\040b\\011c\\012d\\134e";
    let decoded = b"/run/secrets/a b\tc\nd\\e";
    assert!(
        mountinfo::validate_read_only_mount(&mountinfo(escaped, b"ro", b"rw"), decoded).is_ok()
    );

    let cases = [
        ("malformed", b"31 24 malformed\n".to_vec()),
        (
            "unknown escape",
            mountinfo(b"/run/secrets/a\\041b", b"ro", b"rw"),
        ),
        ("missing", mountinfo(b"/run/secrets/other", b"ro", b"rw")),
        (
            "prefix",
            mountinfo(b"/run/secrets/aster-provisioning-bundle-old", b"ro", b"rw"),
        ),
        ("writable", mountinfo(TARGET, b"rw", b"ro")),
    ];
    for (name, bytes) in cases {
        assert_eq!(
            mountinfo::validate_read_only_mount(&bytes, TARGET)
                .expect_err(name)
                .reason(),
            ComposeCredentialReason::InvalidMountBoundary,
            "case {name}"
        );
    }

    let mut duplicate = mountinfo(TARGET, b"ro", b"rw");
    duplicate.extend_from_slice(&mountinfo(TARGET, b"ro", b"rw"));
    assert_eq!(
        mountinfo::validate_read_only_mount(&duplicate, TARGET)
            .expect_err("duplicate exact target")
            .reason(),
        ComposeCredentialReason::InvalidMountBoundary
    );
}

#[test]
fn mountinfo_rejects_malformed_full_width_records() {
    // Break caught: checking only field counts, target, and ro lets malformed
    // Linux mountinfo records establish a false read-only trust boundary.
    let malformed = [
        b"x y z q /run/secrets/aster-provisioning-bundle ro - x y z\n".as_slice(),
        b"31 x 0:28 / /run/secrets/aster-provisioning-bundle ro - tmpfs tmpfs rw\n",
        b"31 24 x:28 / /run/secrets/aster-provisioning-bundle ro - tmpfs tmpfs rw\n",
        b"31 24 0:28 relative /run/secrets/aster-provisioning-bundle ro - tmpfs tmpfs rw\n",
        b"31 24 0:28 / /run/secrets/aster-provisioning-bundle ro bogus - tmpfs tmpfs rw\n",
        b"31 24 0:28 / /run/secrets/aster-provisioning-bundle ro - bad/type tmpfs rw\n",
        b"31 24 0:28 / /run/secrets/aster-provisioning-bundle ro - tmpfs tmp\\041fs rw\n",
        b"31 24 0:28 / /run/secrets/aster-provisioning-bundle ro - tmpfs tmpfs rw,,nodev\n",
    ];
    for record in malformed {
        assert_eq!(
            mountinfo::validate_read_only_mount(record, TARGET)
                .expect_err("malformed full-width mountinfo")
                .reason(),
            ComposeCredentialReason::InvalidMountBoundary,
            "record {record:?}"
        );
    }
}

#[test]
fn mountinfo_input_is_bounded() {
    // Break caught: reading an unbounded proc file permits memory exhaustion
    // before the credential boundary can fail closed.
    let oversized = vec![b'x'; mountinfo::MAX_MOUNTINFO_BYTES + 1];
    assert_eq!(
        mountinfo::validate_read_only_mount(&oversized, TARGET)
            .expect_err("oversized mountinfo")
            .reason(),
        ComposeCredentialReason::TooLarge
    );
}

#[test]
fn mount_must_remain_read_only_after_the_bounded_read() {
    // Break caught: a remount racing the read must not pass merely because
    // the first mountinfo snapshot described the exact target as read-only.
    let uid = rustix::process::geteuid().as_raw();
    let root = TempDirectory::new();
    write_secret(root.path(), "credential", b"canonical", 0o400);
    let error = secret_file::read_secret_for_test_with_mountinfo_after(
        root.path(),
        "credential",
        TARGET,
        [
            &mountinfo(TARGET, b"ro", b"rw"),
            &mountinfo(TARGET, b"rw", b"ro"),
        ],
        uid,
        64,
        secret_file::ReadFault::None,
    )
    .expect_err("writable second mount snapshot");
    assert_eq!(
        error.reason(),
        ComposeCredentialReason::InvalidMountBoundary
    );
}

#[test]
fn diagnostics_never_include_paths_or_fixture_bytes() {
    // Break caught: carrying io::Error or dynamic paths through the public
    // error would disclose deployment layout or credential-bearing values.
    let root = TempDirectory::new();
    let error = read(
        root.path(),
        "known-secret-canary",
        &mountinfo(TARGET, b"ro", b"rw"),
        rustix::process::geteuid().as_raw(),
        64,
        secret_file::ReadFault::None,
    )
    .expect_err("missing fixture");
    let diagnostic = format!("{error:?}");
    assert!(
        !diagnostic.contains(
            root.path()
                .as_os_str()
                .as_bytes()
                .escape_ascii()
                .to_string()
                .as_str()
        )
    );
    assert!(!diagnostic.contains("known-secret-canary"));
}
