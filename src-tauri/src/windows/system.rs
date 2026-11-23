//! Locations the elevated side may trust. Nothing here reads the environment:
//! an elevated process inherits the user's variables (and `HKCU\Environment`
//! can redefine `SystemRoot` or `windir`), so paths come from the system.

use super::{wfp::ObjectSecurity, wide};
use crate::Result;
use std::{
    ffi::{c_void, OsString},
    fs, io,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, INVALID_HANDLE_VALUE,
        },
        Security::{
            Authorization::{GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT},
            GetSecurityDescriptorDacl, IsWellKnownSid, WinBuiltinAdministratorsSid,
            WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
        },
        System::{
            Com::CoTaskMemFree,
            SystemInformation::{GetSystemDirectoryW, GetSystemWindowsDirectoryW},
        },
        UI::Shell::{FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath},
    },
};

/// Folder of the state written by the elevated worker (progress, the backup
/// of the previous firewall policy). Only Administrators and SYSTEM write to
/// it; the panel reads the progress from here.
const STATE_FOLDER: &str = "TunnelGuard";
const STATE_SECURITY: &str = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;AU)";

fn api_path(read: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe { read(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length + 1, 0);
    }
}

/// `C:\Windows`, from the system rather than `%SystemRoot%`.
pub(crate) fn windows_directory() -> Result<PathBuf> {
    api_path(GetSystemWindowsDirectoryW)
}

/// `C:\Windows\System32`, from the system rather than `%SystemRoot%`.
pub(crate) fn system_directory() -> Result<PathBuf> {
    api_path(GetSystemDirectoryW)
}

fn known_folder(id: &GUID) -> Result<PathBuf> {
    let mut raw = null_mut();
    let result = unsafe { SHGetKnownFolderPath(id, 0, null_mut(), &mut raw) };
    let path = (result >= 0 && !raw.is_null()).then(|| {
        let length = (0..).take_while(|&i| unsafe { *raw.add(i) } != 0).count();
        PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(raw, length)
        }))
    });
    unsafe { CoTaskMemFree(raw as *const c_void) };
    path.ok_or_else(|| format!("Windows не вернула системную папку (0x{result:08x})."))
}

/// `%ProgramData%\TunnelGuard`, without creating or checking it.
pub(crate) fn state_directory() -> Result<PathBuf> {
    Ok(known_folder(&FOLDERID_ProgramData)?.join(STATE_FOLDER))
}

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Creates the state folder with a protected ACL, or takes over one that an
/// administrator created. A folder another user created first, or a link in
/// its place, is refused: every later write of the elevated worker would
/// follow it.
pub(crate) fn secure_state_directory() -> Result<PathBuf> {
    let path = state_directory()?;
    let name = wide(path.as_os_str());
    let security = ObjectSecurity::from_sddl(STATE_SECURITY)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.descriptor(),
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } != 0 {
        return Ok(path);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
        return Err(format!("Не удалось создать {}: {error}", path.display()));
    }
    let untrusted = || {
        format!(
            "Папку {} создал не администратор. Удали её и повтори.",
            path.display()
        )
    };
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(untrusted());
    }
    let handle = Handle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !owned_by_administrators(handle.0)?
    {
        return Err(untrusted());
    }
    // An administrator's folder may still carry the inherited ProgramData
    // ACL, which lets users create files in it.
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            security.descriptor(),
            &mut present,
            &mut dacl,
            &mut defaulted,
        )
    } == 0
        || present == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = unsafe {
        SetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(untrusted());
    }
    Ok(path)
}

fn owned_by_administrators(handle: *mut c_void) -> Result<bool> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32).to_string());
    }
    let trusted = unsafe {
        IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            || IsWellKnownSid(owner, WinLocalSystemSid) != 0
    };
    unsafe { LocalFree(descriptor) };
    Ok(trusted)
}

fn normalized(path: &Path) -> Option<String> {
    let path = fs::canonicalize(path).ok()?;
    let mut text = path.to_str()?.to_lowercase();
    if !text.ends_with('\\') {
        text.push('\\');
    }
    Some(text)
}

/// Whether `exe` sits under Program Files, where only administrators can
/// replace it. A copy in a user folder must not be elevated: any program of
/// the user could swap the EXE or plant a DLL next to it first.
pub(crate) fn installed_for_all_users(exe: &Path) -> bool {
    let Ok(root) = known_folder(&FOLDERID_ProgramFiles) else {
        return false;
    };
    match (normalized(&root), exe.parent().and_then(normalized)) {
        (Some(root), Some(folder)) => folder.starts_with(&root) && folder != root,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_folders_come_from_the_api() {
        let windows = windows_directory().unwrap();
        let system = system_directory().unwrap();
        assert!(windows.is_absolute() && windows.join("explorer.exe").is_file());
        assert_eq!(system.parent(), Some(windows.as_path()));
        assert!(system.join("svchost.exe").is_file());
    }

    #[test]
    fn state_folder_is_under_program_data() {
        let state = state_directory().unwrap();
        assert!(state.is_absolute());
        assert!(state.ends_with(STATE_FOLDER));
    }

    #[test]
    fn state_security_descriptor_is_valid() {
        ObjectSecurity::from_sddl(STATE_SECURITY).unwrap();
    }

    #[test]
    fn user_folders_are_not_an_all_users_install() {
        let temp = tempfile::tempdir().unwrap();
        let exe = temp.path().join("tunnel-guard.exe");
        fs::write(&exe, b"").unwrap();
        assert!(!installed_for_all_users(&exe));
        let root = known_folder(&FOLDERID_ProgramFiles).unwrap();
        // Program Files itself is not an install folder.
        assert!(!installed_for_all_users(&root.join("tunnel-guard.exe")));
    }
}
