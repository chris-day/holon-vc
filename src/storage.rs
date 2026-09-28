//! Descriptor-relative Linux storage. No path component is followed through a symlink.
use crate::errors::{Result, error};
use rustix::fs::{self, AtFlags, FlockOperation, Mode, OFlags, RenameFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};
fn fail() -> crate::errors::Error {
    error(
        "UNSAFE_STORAGE",
        "storage",
        "File access failed, permissions are unsafe, or path contains a symlink",
    )
}

pub fn directory(path: &Path, create: bool) -> Result<File> {
    let mut dir = File::from(
        fs::open(
            if path.is_absolute() { "/" } else { "." },
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| fail())?,
    );
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => (),
            Component::Normal(name) => {
                if create {
                    match fs::mkdirat(&dir, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) => (),
                        Err(e) if e == rustix::io::Errno::EXIST => (),
                        Err(_) => return Err(fail()),
                    }
                }
                dir = File::from(
                    fs::openat(
                        &dir,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| fail())?,
                );
            }
            _ => return Err(fail()),
        }
    }
    Ok(dir)
}
fn parent(path: &Path, create: bool) -> Result<(File, &std::ffi::OsStr)> {
    Ok((
        directory(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
            create,
        )?,
        path.file_name().ok_or_else(fail)?,
    ))
}
fn secure(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|_| fail())?;
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err(fail());
    }
    Ok(())
}
pub fn read(path: &Path, private: bool) -> Result<Vec<u8>> {
    let (dir, name) = parent(path, false)?;
    if private {
        secure(&dir)?;
    }
    let file = File::from(
        fs::openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| fail())?,
    );
    let m = file.metadata().map_err(|_| fail())?;
    if !m.is_file() || m.len() > 4 * 1024 * 1024 || (private && m.nlink() != 1) {
        return Err(fail());
    }
    if private {
        secure(&file)?;
    }
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| fail())?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(fail());
    }
    Ok(bytes)
}
pub fn read_json(path: &Path) -> Result<serde_json::Value> {
    crate::models::parse(&read(path, false)?)
}
pub fn write(path: &Path, bytes: &[u8], private: bool, force: bool) -> Result<()> {
    let (dir, name) = parent(path, true)?;
    if private {
        secure(&dir)?;
    }
    if let Ok(stat) = fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW)
        && (stat.st_mode & 0o170000 != 0o100000 || !force)
    {
        return Err(error(
            "OUTPUT_EXISTS",
            "storage",
            "Output exists or is not a regular file; explicit --force is required",
        ));
    }
    let temp = format!(".holon-{}.tmp", uuid::Uuid::new_v4());
    let mut file = File::from(
        fs::openat(
            &dir,
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(if private { 0o600 } else { 0o644 }),
        )
        .map_err(|_| fail())?,
    );
    let result = (|| {
        file.write_all(bytes).map_err(|_| fail())?;
        file.sync_all().map_err(|_| fail())?;
        fs::renameat_with(
            &dir,
            &temp,
            &dir,
            name,
            if force {
                RenameFlags::empty()
            } else {
                RenameFlags::NOREPLACE
            },
        )
        .map_err(|_| fail())?;
        dir.sync_all().map_err(|_| fail())
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&dir, &temp, AtFlags::empty());
    }
    result
}
pub fn write_json(
    path: &Path,
    value: &impl serde::Serialize,
    private: bool,
    force: bool,
) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(value).map_err(|_| fail())?;
    b.push(b'\n');
    write(path, &b, private, force)
}
pub fn lock(root: &Path) -> Result<File> {
    let dir = directory(root, true)?;
    secure(&dir)?;
    let file = File::from(
        fs::openat(
            &dir,
            ".lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| fail())?,
    );
    secure(&file)?;
    fs::flock(&file, FlockOperation::LockExclusive).map_err(|_| fail())?;
    Ok(file)
}
pub fn remove(path: &Path) -> Result<()> {
    let (dir, name) = parent(path, false)?;
    let stat = fs::statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| fail())?;
    if stat.st_mode & 0o170000 != 0o100000 {
        return Err(fail());
    }
    fs::unlinkat(&dir, name, AtFlags::empty()).map_err(|_| fail())?;
    dir.sync_all().map_err(|_| fail())
}
pub fn safe_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        Err(error(
            "INVALID_ID",
            "structure",
            "Local IDs must use letters, digits, hyphens or underscores",
        ))
    } else {
        Ok(())
    }
}
pub fn digest(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
