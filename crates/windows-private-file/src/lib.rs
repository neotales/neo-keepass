//! Windows security descriptors for private application files.
//!
//! Like the Unix path-based staging code, this assumes the containing directory
//! is not concurrently controlled by an adversary. It does not protect against
//! administrators, backup privileges, or other processes running as the user.
//!
//! The FFI boundary owns every returned handle and `LocalAlloc` buffer. SID and
//! ACL pointers are only borrowed while their containing buffers remain live;
//! no pointer is exposed to callers. Security descriptors returned by Windows
//! are inspected before this module hands out a writable file.

#![cfg(windows)]

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetTokenInformation,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct Token(*mut c_void);
impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn user_sid() -> io::Result<Vec<u8>> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Token(token);
        let mut size = 0;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &raw mut size);
        if size == 0 {
            return Err(io::Error::last_os_error());
        }
        // TOKEN_USER requires pointer alignment, so use a usize buffer.
        let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        if GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &raw mut size,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sid = (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid;
        let mut text = null_mut();
        if ConvertSidToStringSidW(sid, &raw mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let owned = Local(text.cast());
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        let result = std::slice::from_raw_parts(text, length)
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        drop(owned);
        Ok(result)
    }
}

fn descriptor() -> io::Result<Local> {
    let sid = user_sid()?;
    let sid: Vec<u16> = sid
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    let mut sddl: Vec<u16> = "O:".encode_utf16().collect();
    sddl.extend_from_slice(&sid);
    sddl.extend("D:P(A;;FA;;;".encode_utf16());
    sddl.extend_from_slice(&sid);
    sddl.extend(")".encode_utf16());
    sddl.push(0);
    unsafe {
        let mut sd = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut sd,
            null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Local(sd))
    }
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    value.push(0);
    Ok(value)
}

/// Creates a new file with a protected current-user-only DACL before any data
/// can be written.
///
/// # Errors
///
/// Returns an error if creation or descriptor verification fails.
pub fn create_new(path: &Path) -> io::Result<File> {
    let sd = descriptor()?;
    let path_wide = wide(path)?;
    unsafe {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| io::Error::other("security attributes size overflow"))?,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let handle = CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = File::from_raw_handle(handle);
        if let Err(error) = verify(&file) {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(file)
    }
}

/// Checks that the file has a protected DACL granting only the current user.
///
/// # Errors
///
/// Returns an error if the descriptor cannot be read or is not private.
pub fn verify(file: &File) -> io::Result<()> {
    unsafe {
        let expected = descriptor()?;
        let mut present = 0;
        let mut defaulted = 0;
        let mut desired_dacl = null_mut();
        if GetSecurityDescriptorDacl(
            expected.0,
            &raw mut present,
            &raw mut desired_dacl,
            &raw mut defaulted,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || desired_dacl.is_null() {
            return Err(io::Error::other("missing expected DACL"));
        }
        let mut desired_entry = null_mut();
        if GetAce(desired_dacl, 0, &raw mut desired_entry) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut owner: PSID = null_mut();
        let mut acl: *mut ACL = null_mut();
        let mut raw_sd: PSECURITY_DESCRIPTOR = null_mut();
        let code = GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut acl,
            null_mut(),
            &raw mut raw_sd,
        );
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code.cast_signed()));
        }
        let sd = Local(raw_sd);
        let mut control = 0;
        let mut revision = 0;
        let mut ace = null_mut();
        let desired_entry = &*(desired_entry.cast::<ACCESS_ALLOWED_ACE>());
        let valid = !acl.is_null()
            && !owner.is_null()
            && (*acl).AceCount == 1
            && GetSecurityDescriptorControl(sd.0, &raw mut control, &raw mut revision) != 0
            && control & SE_DACL_PROTECTED != 0
            && GetAce(acl, 0, &raw mut ace) != 0
            && !ace.is_null()
            && u32::from((*(ace.cast::<ACCESS_ALLOWED_ACE>())).Header.AceType)
                == ACCESS_ALLOWED_ACE_TYPE
            && (*(ace.cast::<ACCESS_ALLOWED_ACE>())).Header.AceFlags == 0
            && (*(ace.cast::<ACCESS_ALLOWED_ACE>())).Mask == desired_entry.Mask
            && EqualSid(
                (&raw const (*(ace.cast::<ACCESS_ALLOWED_ACE>())).SidStart)
                    .cast_mut()
                    .cast(),
                (&raw const desired_entry.SidStart).cast_mut().cast(),
            ) != 0
            && EqualSid(owner, (&raw const desired_entry.SidStart).cast_mut().cast()) != 0;
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private DACL verification failed",
            ));
        }
        Ok(())
    }
}

/// Replaces a directory's DACL with a protected current-user-only DACL.
///
/// # Errors
///
/// Returns an error if the directory cannot be secured or verified. A failed
/// verification may leave its DACL changed.
pub fn secure_directory(path: &Path) -> io::Result<()> {
    let path = wide(path)?;
    let sd = descriptor()?;
    unsafe {
        let handle = CreateFileW(
            path.as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = File::from_raw_handle(handle);
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        if GetSecurityDescriptorDacl(sd.0, &raw mut present, &raw mut acl, &raw mut defaulted) == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SetSecurityInfo interprets a null DACL as granting everyone access.
        if present == 0 || acl.is_null() {
            return Err(io::Error::other("missing private DACL"));
        }
        let code = SetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        );
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code.cast_signed()));
        }
        verify(&file)
    }
}
