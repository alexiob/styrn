#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "windows"
}

use super::ManifestOwner;
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_FILE_OBJECT: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const WIN_LOCAL_SYSTEM_SID: i32 = 22;
const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
const FILE_READ: u32 = 0x0012_0089;
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
const MUTATING_ACCESS: u32 = 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x4000_0000
    | 0x1000_0000;

#[repr(C)]
struct Acl {
    revision: u8,
    sbz1: u8,
    size: u16,
    ace_count: u16,
    sbz2: u16,
}

#[repr(C)]
struct TrusteeW {
    multiple_trustee: *mut TrusteeW,
    multiple_trustee_operation: i32,
    trustee_form: i32,
    trustee_type: i32,
    name: *mut u16,
}

#[derive(Clone, Copy)]
enum AclKind {
    Manifest,
    Directory,
    Lock,
}

struct AclInspection {
    owner_is_administrators: bool,
    dacl_is_protected: bool,
    worker_rights: u32,
    system_rights: u32,
    administrator_rights: u32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        security_descriptor: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn SetFileSecurityW(
        file_name: *const u16,
        security_information: u32,
        security_descriptor: *const c_void,
    ) -> i32;
    fn LookupAccountNameW(
        system_name: *const u16,
        account_name: *const u16,
        sid: *mut c_void,
        sid_size: *mut u32,
        referenced_domain_name: *mut u16,
        domain_size: *mut u32,
        sid_name_use: *mut i32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
    fn GetNamedSecurityInfoW(
        object_name: *mut u16,
        object_type: u32,
        security_information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut Acl,
        sacl: *mut *mut Acl,
        security_descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorControl(
        security_descriptor: *const c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetEffectiveRightsFromAclW(
        acl: *const Acl,
        trustee: *const TrusteeW,
        access_rights: *mut u32,
    ) -> u32;
    fn CreateWellKnownSid(
        sid_type: i32,
        domain_sid: *const c_void,
        sid: *mut c_void,
        sid_size: *mut u32,
    ) -> i32;
    fn EqualSid(first: *const c_void, second: *const c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

pub(crate) fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    let existing: Vec<u16> = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let replacement: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    if unsafe {
        MoveFileExW(
            existing.as_ptr(),
            replacement.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    require_kind(path, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    apply_acl(path, worker, AclKind::Directory)?;
    inspect_acl(path, worker, AclKind::Directory)
}

pub(super) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    require_kind(path, false)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    apply_acl(path, worker, AclKind::Manifest)?;
    inspect_acl(path, worker, AclKind::Manifest)
}

pub(super) fn harden_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<()> {
    require_kind(path, false)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    apply_acl(path, "styrn", AclKind::Lock)?;
    inspect_acl(path, "styrn", AclKind::Lock)
}

pub(super) fn open_manifest_lock(path: &Path, owner: ManifestOwner) -> io::Result<std::fs::File> {
    let created = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path);
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            harden_manifest_lock(path, owner)?;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
        }
        Err(error) => return Err(error),
    };
    harden_manifest_lock(path, owner)?;
    Ok(file)
}

pub(super) fn create_manifest_temporary(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

pub(super) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &str,
) -> io::Result<()> {
    require_kind(path, false)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_kind(parent, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    inspect_acl(parent, worker, AclKind::Directory)?;
    inspect_acl(path, worker, AclKind::Manifest)
}

fn is_test_owner(owner: ManifestOwner) -> bool {
    match owner {
        ManifestOwner::System => false,
        #[cfg(test)]
        ManifestOwner::CurrentProcess => true,
    }
}

fn apply_acl(path: &Path, worker: &str, kind: AclKind) -> io::Result<()> {
    let worker_sid = lookup_account_sid(worker)?;
    let worker_sid_string = sid_to_string(worker_sid.as_ptr().cast())?;
    let sddl = acl_sddl(&worker_sid_string, kind);
    let wide_sddl = wide(&sddl);
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let wide_path = wide_os(path);
    if unsafe {
        SetFileSecurityW(
            wide_path.as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn acl_sddl(worker_sid: &str, kind: AclKind) -> String {
    match kind {
        AclKind::Manifest => {
            format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;{worker_sid})")
        }
        AclKind::Directory => {
            format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{worker_sid})")
        }
        AclKind::Lock => "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned(),
    }
}

fn inspect_acl(path: &Path, worker: &str, kind: AclKind) -> io::Result<()> {
    let mut path = wide_os(path);
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path.as_mut_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalAllocation(descriptor);
    if dacl.is_null() || owner.is_null() {
        return Err(permission_denied(
            "manifest security descriptor is incomplete",
        ));
    }

    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let worker = lookup_account_sid(worker)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let inspection = AclInspection {
        owner_is_administrators: unsafe { EqualSid(owner, administrators.as_ptr().cast()) } != 0,
        dacl_is_protected: control & SE_DACL_PROTECTED != 0,
        worker_rights: effective_rights(dacl, worker.as_ptr().cast_mut().cast())?,
        system_rights: effective_rights(dacl, system.as_ptr().cast_mut().cast())?,
        administrator_rights: effective_rights(dacl, administrators.as_ptr().cast_mut().cast())?,
    };
    validate_acl_contract(&inspection, kind)
}

fn validate_acl_contract(inspection: &AclInspection, kind: AclKind) -> io::Result<()> {
    if !inspection.owner_is_administrators {
        return Err(permission_denied(
            "manifest ACL owner must be Administrators",
        ));
    }
    if !inspection.dacl_is_protected {
        return Err(permission_denied(
            "manifest DACL must be protected from inherited grants",
        ));
    }
    if inspection.system_rights & FILE_ALL_ACCESS != FILE_ALL_ACCESS
        || inspection.administrator_rights & FILE_ALL_ACCESS != FILE_ALL_ACCESS
    {
        return Err(permission_denied(
            "SYSTEM and Administrators must retain full control",
        ));
    }
    match kind {
        AclKind::Manifest => {
            if inspection.worker_rights & FILE_READ != FILE_READ
                || inspection.worker_rights & MUTATING_ACCESS != 0
                || inspection.worker_rights & !(FILE_READ) != 0
            {
                return Err(permission_denied(
                    "styrn worker must have read-only manifest access",
                ));
            }
        }
        AclKind::Directory => {
            if inspection.worker_rights & FILE_READ != FILE_READ
                || inspection.worker_rights & FILE_EXECUTE == 0
                || inspection.worker_rights & MUTATING_ACCESS != 0
                || inspection.worker_rights & !(FILE_READ | FILE_EXECUTE) != 0
            {
                return Err(permission_denied(
                    "styrn worker must not have directory replacement access",
                ));
            }
        }
        AclKind::Lock => {
            if inspection.worker_rights != 0 {
                return Err(permission_denied(
                    "styrn worker must not access the manifest lock",
                ));
            }
        }
    }
    Ok(())
}

fn effective_rights(acl: *const Acl, sid: *mut u16) -> io::Result<u32> {
    let trustee = TrusteeW {
        multiple_trustee: std::ptr::null_mut(),
        multiple_trustee_operation: 0,
        trustee_form: 0,
        trustee_type: 0,
        name: sid,
    };
    let mut rights = 0;
    let status = unsafe { GetEffectiveRightsFromAclW(acl, &trustee, &mut rights) };
    if status == 0 {
        Ok(rights)
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

fn lookup_account_sid(account: &str) -> io::Result<Vec<u8>> {
    let account = wide(account);
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut sid_use = 0;
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0_u8; sid_size as usize];
    let mut domain = vec![0_u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

fn well_known_sid(kind: i32) -> io::Result<Vec<u8>> {
    let mut size = 68;
    let mut sid = vec![0_u8; size as usize];
    if unsafe { CreateWellKnownSid(kind, std::ptr::null(), sid.as_mut_ptr().cast(), &mut size) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    sid.truncate(size as usize);
    Ok(sid)
}

fn sid_to_string(sid: *const c_void) -> io::Result<String> {
    let mut string = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let string = LocalWideString(string);
    let length = (0..)
        .take_while(|&index| unsafe { *string.0.add(index) } != 0)
        .count();
    String::from_utf16(unsafe { std::slice::from_raw_parts(string.0, length) })
        .map_err(|_| invalid_data("Windows returned a non-UTF-16 SID string"))
}

fn require_kind(path: &Path, directory: bool) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    let valid = if directory {
        metadata.file_type().is_dir()
    } else {
        metadata.file_type().is_file()
    };
    if !valid {
        return Err(invalid_data("manifest ACL target has the wrong file type"));
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_os(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn permission_denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.to_owned())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructed_acl_is_protected_and_grants_only_the_documented_principals() {
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::Manifest),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::Directory),
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn inspection_rejects_inherited_or_explicit_worker_mutation_rights() {
        let inherited_write = AclInspection {
            owner_is_administrators: true,
            dacl_is_protected: false,
            worker_rights: FILE_READ | 0x2,
            system_rights: FILE_ALL_ACCESS,
            administrator_rights: FILE_ALL_ACCESS,
        };
        assert!(validate_acl_contract(&inherited_write, AclKind::Manifest).is_err());

        let explicit_write = AclInspection {
            dacl_is_protected: true,
            ..inherited_write
        };
        assert!(validate_acl_contract(&explicit_write, AclKind::Manifest).is_err());
    }

    #[test]
    fn inspection_accepts_exact_read_only_worker_contract() {
        let inspection = AclInspection {
            owner_is_administrators: true,
            dacl_is_protected: true,
            worker_rights: FILE_READ,
            system_rights: FILE_ALL_ACCESS,
            administrator_rights: FILE_ALL_ACCESS,
        };
        assert!(validate_acl_contract(&inspection, AclKind::Manifest).is_ok());
    }

    #[test]
    #[ignore = "environmental: run elevated on Windows with a real styrn account"]
    fn real_windows_acl_round_trip_requires_administrator_and_worker_account() {
        let directory = std::env::temp_dir().join(format!(
            "styrn-acl-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        harden_manifest_directory(&directory, ManifestOwner::System, "styrn").unwrap();
        let manifest = directory.join("machine.toml");
        std::fs::write(&manifest, "schema_version = 1\n").unwrap();
        harden_manifest_file(&manifest, ManifestOwner::System, "styrn").unwrap();
        verify_manifest_security(&manifest, ManifestOwner::System, "styrn").unwrap();
        std::fs::remove_file(manifest).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
