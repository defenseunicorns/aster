use crate::{ComposeCredentialError, ComposeCredentialReason};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use std::{
    fs::File,
    io::Read as _,
    os::unix::ffi::OsStrExt as _,
    path::{Component, Path},
};

#[cfg(all(test, target_os = "linux"))]
use std::os::unix::fs::PermissionsExt as _;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileMetadata {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
    links: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

#[cfg(any(test, target_os = "linux"))]
pub(super) fn normalize_link_count<T: Into<u64>>(links: T) -> u64 {
    links.into()
}

#[cfg(target_os = "linux")]
impl FileMetadata {
    fn from_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            owner: stat.st_uid,
            mode: stat.st_mode,
            links: normalize_link_count(stat.st_nlink),
            size: stat.st_size,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) fn read_fixed_secret(
    target: &str,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    let target = Path::new(target);
    let root = target
        .parent()
        .ok_or_else(|| error(ComposeCredentialReason::InvalidMountBoundary))?;
    let basename = target
        .file_name()
        .ok_or_else(|| error(ComposeCredentialReason::InvalidMountBoundary))?;
    let mountinfo = read_mountinfo()?;
    let bytes = read_secret_inner(
        root,
        basename,
        target.as_os_str().as_bytes(),
        &mountinfo,
        rustix::process::geteuid().as_raw(),
        max_bytes,
        || Ok(()),
    )?;
    let mountinfo_after = read_mountinfo()?;
    crate::mountinfo::validate_read_only_mount(&mountinfo_after, target.as_os_str().as_bytes())?;
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn read_fixed_secret(
    _target: &str,
    _max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    Err(error(ComposeCredentialReason::UnsupportedPlatform))
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn read_mountinfo() -> Result<Vec<u8>, ComposeCredentialError> {
    let file = File::open("/proc/self/mountinfo")
        .map_err(|_| error(ComposeCredentialReason::FileAccess))?;
    let mut bytes = Vec::new();
    file.take((crate::mountinfo::MAX_MOUNTINFO_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| error(ComposeCredentialReason::FileAccess))?;
    if bytes.len() > crate::mountinfo::MAX_MOUNTINFO_BYTES {
        return Err(error(ComposeCredentialReason::TooLarge));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn read_secret_inner(
    root: &Path,
    basename: &std::ffi::OsStr,
    target: &[u8],
    mountinfo: &[u8],
    effective_uid: u32,
    max_bytes: usize,
    after_read: impl FnOnce() -> Result<(), ComposeCredentialError>,
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    crate::mountinfo::validate_read_only_mount(mountinfo, target)?;
    validate_root_and_basename(root, basename)?;
    let root_descriptor = open_root(root)?;
    let metadata_descriptor = rustix::fs::openat2(
        &root_descriptor,
        basename,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
        resolve_flags(),
    )
    .map_err(map_open_error)?;
    let path_metadata = FileMetadata::from_stat(
        &rustix::fs::fstat(&metadata_descriptor)
            .map_err(|_| error(ComposeCredentialReason::FileAccess))?,
    );
    validate_metadata(&path_metadata, effective_uid, max_bytes)?;
    let descriptor = rustix::fs::openat2(
        &root_descriptor,
        basename,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
        resolve_flags(),
    )
    .map_err(map_open_error)?;
    let mut file = File::from(descriptor);
    let before = FileMetadata::from_stat(
        &rustix::fs::fstat(&file).map_err(|_| error(ComposeCredentialReason::FileAccess))?,
    );
    validate_metadata(&before, effective_uid, max_bytes)?;
    if path_metadata != before {
        return Err(error(ComposeCredentialReason::Changed));
    }
    let declared =
        usize::try_from(before.size).map_err(|_| error(ComposeCredentialReason::TooLarge))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(declared));
    let read_bound = max_bytes
        .checked_add(1)
        .ok_or_else(|| error(ComposeCredentialReason::TooLarge))?;
    (&mut file)
        .take(read_bound as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| error(ComposeCredentialReason::FileAccess))?;
    if bytes.len() > max_bytes {
        return Err(error(ComposeCredentialReason::TooLarge));
    }
    after_read()?;
    let after = FileMetadata::from_stat(
        &rustix::fs::fstat(&file).map_err(|_| error(ComposeCredentialReason::FileAccess))?,
    );
    validate_metadata(&after, effective_uid, max_bytes)?;
    if before != after || bytes.len() != declared {
        return Err(error(ComposeCredentialReason::Changed));
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn open_root(root: &Path) -> Result<rustix::fd::OwnedFd, ComposeCredentialError> {
    let relative = root
        .strip_prefix("/")
        .map_err(|_| error(ComposeCredentialReason::InvalidMountBoundary))?;
    if relative.as_os_str().is_empty() {
        return Err(error(ComposeCredentialReason::InvalidMountBoundary));
    }
    let slash = rustix::fs::openat(
        rustix::fs::CWD,
        "/",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| error(ComposeCredentialReason::FileAccess))?;
    rustix::fs::openat2(
        slash,
        relative,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
        resolve_flags(),
    )
    .map_err(map_open_error)
}

#[cfg(target_os = "linux")]
fn resolve_flags() -> rustix::fs::ResolveFlags {
    rustix::fs::ResolveFlags::BENEATH
        | rustix::fs::ResolveFlags::NO_SYMLINKS
        | rustix::fs::ResolveFlags::NO_MAGICLINKS
}

#[cfg(target_os = "linux")]
fn validate_root_and_basename(
    root: &Path,
    basename: &std::ffi::OsStr,
) -> Result<(), ComposeCredentialError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || Path::new(basename).components().count() != 1
        || !matches!(
            Path::new(basename).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(error(ComposeCredentialReason::InvalidMountBoundary));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_metadata(
    metadata: &FileMetadata,
    effective_uid: u32,
    max_bytes: usize,
) -> Result<(), ComposeCredentialError> {
    let file_type = rustix::fs::FileType::from_raw_mode(metadata.mode);
    if file_type == rustix::fs::FileType::Symlink {
        return Err(error(ComposeCredentialReason::InvalidMountBoundary));
    }
    if file_type != rustix::fs::FileType::RegularFile {
        return Err(error(ComposeCredentialReason::NotRegular));
    }
    if metadata.links != 1 {
        return Err(error(ComposeCredentialReason::LinkCount));
    }
    if effective_uid == 0 || metadata.owner != effective_uid {
        return Err(error(ComposeCredentialReason::Ownership));
    }
    if !matches!(metadata.mode & 0o7777, 0o400 | 0o600) {
        return Err(error(ComposeCredentialReason::Permissions));
    }
    if metadata.size < 0 || usize::try_from(metadata.size).map_or(true, |size| size > max_bytes) {
        return Err(error(ComposeCredentialReason::TooLarge));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn map_open_error(error_value: rustix::io::Errno) -> ComposeCredentialError {
    if matches!(
        error_value,
        rustix::io::Errno::LOOP | rustix::io::Errno::XDEV | rustix::io::Errno::NOTDIR
    ) {
        error(ComposeCredentialReason::InvalidMountBoundary)
    } else {
        error(ComposeCredentialReason::FileAccess)
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub(crate) enum ReadFault {
    None,
    Truncate,
}

#[cfg(all(test, target_os = "linux"))]
#[allow(dead_code)]
pub(crate) fn read_secret_for_test(
    root: &Path,
    basename: &str,
    target: &[u8],
    mountinfo: &[u8],
    effective_uid: u32,
    max_bytes: usize,
    fault: ReadFault,
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    read_secret_for_test_with_mountinfo_after(
        root,
        basename,
        target,
        [mountinfo, mountinfo],
        effective_uid,
        max_bytes,
        fault,
    )
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn read_secret_for_test_with_mountinfo_after(
    root: &Path,
    basename: &str,
    target: &[u8],
    mountinfo: [&[u8]; 2],
    effective_uid: u32,
    max_bytes: usize,
    fault: ReadFault,
) -> Result<Zeroizing<Vec<u8>>, ComposeCredentialError> {
    let bytes = read_secret_inner(
        root,
        std::ffi::OsStr::new(basename),
        target,
        mountinfo[0],
        effective_uid,
        max_bytes,
        || match fault {
            ReadFault::None => Ok(()),
            ReadFault::Truncate => {
                let path = root.join(basename);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .map_err(|_| error(ComposeCredentialReason::FileAccess))?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(path)
                    .and_then(|file| file.set_len(0))
                    .map_err(|_| error(ComposeCredentialReason::FileAccess))
            }
        },
    )?;
    crate::mountinfo::validate_read_only_mount(mountinfo[1], target)?;
    Ok(bytes)
}

const fn error(reason: ComposeCredentialReason) -> ComposeCredentialError {
    ComposeCredentialError::new(reason)
}
