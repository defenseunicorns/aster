//! Descriptor-relative journal filesystem operations shared with the agent SDK.
//! No pathname is resolved again after acquiring the parent directory.

use std::{fs::File, io, path::Path};

/// Internal journal directory capability. Non-Unix hosts fail closed.
#[doc(hidden)]
pub struct JournalDirectory(File);

impl JournalDirectory {
    /// Uses a caller-retained directory without resolving a descriptor pathname.
    pub fn from_file(directory: &File, name: &Path) -> io::Result<Self> {
        if name.file_name() != Some(name.as_os_str()) || !directory.metadata()?.is_dir() {
            return Err(io::Error::other(
                "expected a directory and a single journal filename",
            ));
        }
        Ok(Self(directory.try_clone()?))
    }

    /// Walks without following symlinks; optionally creates private parents.
    /// Each child and its retained parent are synced before proceeding.
    pub fn open(path: &Path, create_parents: bool) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
            use std::path::Component;
            if path.file_name().is_none() {
                return Err(io::Error::other("journal filename missing"));
            }
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let mut directory = File::from(open(
                if path.is_absolute() { "/" } else { "." },
                flags,
                Mode::empty(),
            )?);
            for component in path.parent().unwrap_or(Path::new(".")).components() {
                let name = match component {
                    Component::RootDir | Component::CurDir => continue,
                    Component::Normal(name) => name,
                    _ => return Err(io::Error::other("journal parent traversal is not allowed")),
                };
                let child = match openat(&directory, name, flags, Mode::empty()) {
                    Ok(fd) => File::from(fd),
                    Err(rustix::io::Errno::NOENT) if create_parents => {
                        match mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                            Ok(()) | Err(rustix::io::Errno::EXIST) => (),
                            Err(error) => return Err(error.into()),
                        }
                        File::from(openat(&directory, name, flags, Mode::empty())?)
                    }
                    Err(error) => return Err(error.into()),
                };
                // Sync even an existing edge when initializing: a prior failed
                // initialization may have created it without completing fsync.
                if create_parents {
                    child.sync_all()?;
                    directory.sync_all()?;
                }
                directory = child;
            }
            Ok(Self(directory))
        }
        #[cfg(not(unix))]
        {
            let _ = (path, create_parents);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "descriptor-relative journals require Unix",
            ))
        }
    }

    /// Opens only the journal basename in this retained directory.
    pub fn file(&self, path: &Path, create: bool) -> io::Result<File> {
        #[cfg(unix)]
        {
            use rustix::fs::{Mode, OFlags, openat};
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let name = path
                .file_name()
                .ok_or_else(|| io::Error::other("journal filename missing"))?;
            let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
            if create {
                flags |= OFlags::CREATE | OFlags::EXCL;
            }
            let file = File::from(openat(&self.0, name, flags, Mode::from_raw_mode(0o600))?);
            if create {
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || (!create && metadata.len() == 0)
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(io::Error::other(
                    "journal must be owned, private, regular and nonempty on open",
                ));
            }
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, create);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "descriptor-relative journals require Unix",
            ))
        }
    }

    /// Synchronizes the directory used to open/create the file, not its old name.
    pub fn sync(&self) -> io::Result<()> {
        self.0.sync_all()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn creation_uses_retained_parent_after_path_replacement() {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        // Resolve the test environment only; journal paths must still reject symlinks.
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory")
            .join(format!("aster-journal-directory-{nonce:x?}"));
        std::fs::create_dir(&root).unwrap();
        let parent = root.join("parent");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("journal");
        let directory = JournalDirectory::open(&path, false).unwrap();
        let moved = root.join("moved");
        std::fs::rename(&parent, &moved).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        let file = directory.file(&path, true).unwrap();
        assert_eq!(
            file.metadata().unwrap().ino(),
            std::fs::metadata(moved.join("journal")).unwrap().ino()
        );
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        file.sync_all().unwrap();
        directory.sync().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert!(directory.file(&path, true).is_err());
        symlink(&path, moved.join("link")).unwrap();
        assert!(directory.file(Path::new("link"), false).is_err());
        assert!(directory.file(Path::new("link"), true).is_err());
        drop(file);
        drop(directory);
        std::fs::remove_dir_all(root).unwrap();
    }
}
