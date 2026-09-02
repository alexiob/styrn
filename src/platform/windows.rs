#[allow(dead_code)]
pub(crate) fn platform_name() -> &'static str {
    "windows"
}

use super::{
    select_windows_user_token, windows_token_posture_from_native, ManifestOwner, PrincipalKind,
    PrivateFileIdentity, SetupExecutionContext, SetupHostPrivilege, WindowsTokenElevationType,
    WindowsTokenPosture, WindowsUserTokenChoice, WorkerPrincipal,
};
use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivatePublicationPhase {
    WriteThroughMove,
    DestinationIdentityVerified,
}

#[cfg(test)]
thread_local! {
    static TRACE_PRIVATE_PUBLICATION: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static PRIVATE_PUBLICATION_TRACE: std::cell::RefCell<Vec<PrivatePublicationPhase>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
fn trace_private_publication_for_test(enabled: bool) {
    TRACE_PRIVATE_PUBLICATION.with(|trace| trace.set(enabled));
    PRIVATE_PUBLICATION_TRACE.with(|phases| phases.borrow_mut().clear());
}

#[cfg(test)]
fn record_private_publication_phase(phase: PrivatePublicationPhase) {
    TRACE_PRIVATE_PUBLICATION.with(|trace| {
        if trace.get() {
            PRIVATE_PUBLICATION_TRACE.with(|phases| phases.borrow_mut().push(phase));
        }
    });
}

#[cfg(test)]
fn take_private_publication_trace_for_test() -> Vec<PrivatePublicationPhase> {
    TRACE_PRIVATE_PUBLICATION.with(|trace| trace.set(false));
    PRIVATE_PUBLICATION_TRACE.with(|phases| std::mem::take(&mut *phases.borrow_mut()))
}

const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_FILE_OBJECT: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_USER_CLASS: u32 = 1;
const TOKEN_GROUPS_CLASS: u32 = 2;
const TOKEN_ELEVATION_TYPE_CLASS: u32 = 18;
const TOKEN_LINKED_TOKEN_CLASS: u32 = 19;
const TOKEN_INTEGRITY_LEVEL_CLASS: u32 = 25;
const SECURITY_IMPERSONATION: u32 = 2;
const TOKEN_PRIMARY: u32 = 1;
const SID_TYPE_USER: i32 = 1;
const WIN_LOCAL_SYSTEM_SID: i32 = 22;
const WIN_BUILTIN_ADMINISTRATORS_SID: i32 = 26;
const FILE_READ: u32 = 0x0012_0089;
const FILE_EXECUTE: u32 = 0x0000_0020;
const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const OBJECT_INHERIT_ACE: u8 = 0x01;
const CONTAINER_INHERIT_ACE: u8 = 0x02;
const INHERIT_ONLY_ACE: u8 = 0x08;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const INVALID_FILE_ATTRIBUTES: u32 = 0xffff_ffff;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
const DELETE_ACCESS: u32 = 0x0001_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const CREATE_NEW: u32 = 1;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_TRAVERSE: u32 = 0x0000_0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_ID_INFO_CLASS: u32 = 18;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const PARENT_TAKEOVER_ACCESS: u32 =
    0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x4000_0000 | 0x1000_0000;
const FILE_MUTATION_ACCESS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x4000_0000
    | 0x1000_0000;
const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
const SEE_MASK_NOASYNC: u32 = 0x0000_0100;
const SW_SHOWNORMAL: i32 = 1;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_ABANDONED_0: u32 = 0x0000_0080;
const CSTR_EQUAL: i32 = 2;
const INFINITE: u32 = 0xffff_ffff;
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const COINIT_DISABLE_OLE1DDE: u32 = 0x4;
const RPC_E_CHANGED_MODE: i32 = 0x8001_0106_u32 as i32;

#[repr(C)]
struct Acl {
    revision: u8,
    sbz1: u8,
    size: u16,
    ace_count: u16,
    sbz2: u16,
}

#[repr(C)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
}

#[repr(C)]
struct AccessAllowedAce {
    header: AceHeader,
    mask: u32,
    sid_start: u32,
}

#[derive(Clone, Copy)]
enum AclKind {
    Manifest,
    Directory,
    Lock,
    Staging,
    UserFile,
    UserDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Principal {
    System,
    Administrators,
    TrustedInstaller,
    Worker,
    Unexpected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserAncestorOwner {
    User,
    TrustedSystem,
    Unexpected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AceInspection {
    principal: Principal,
    mask: u32,
    flags: u8,
    allowed: bool,
}

struct AclInspection {
    owner_matches_policy: bool,
    dacl_is_protected: bool,
    entries: Vec<AceInspection>,
}

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenUser {
    user: SidAndAttributes,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenGroups {
    group_count: u32,
    groups: [SidAndAttributes; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenMandatoryLabel {
    label: SidAndAttributes,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenLinkedToken {
    linked_token: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LuidAndAttributes {
    luid: Luid,
    attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TokenPrivileges {
    privilege_count: u32,
    privileges: [LuidAndAttributes; 1],
}

#[repr(C)]
struct ShellExecuteInfoW {
    size: u32,
    mask: u32,
    window: *mut c_void,
    verb: *const u16,
    file: *const u16,
    parameters: *const u16,
    directory: *const u16,
    show: i32,
    instance: *mut c_void,
    id_list: *mut c_void,
    class: *const u16,
    class_key: *mut c_void,
    hot_key: u32,
    icon_or_monitor: *mut c_void,
    process: *mut c_void,
}

#[repr(C)]
#[allow(dead_code)] // Used by the deferred T0.14 Windows action integration.
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[allow(dead_code)] // Used by the deferred T0.14 Windows action integration.
const FOLDER_ID_LOCAL_APP_DATA: Guid = Guid {
    data1: 0xf1b3_2785,
    data2: 0x6fba,
    data3: 0x4fcf,
    data4: [0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91],
};

#[allow(dead_code)] // Used by the deferred T0.14 Windows action integration.
const FOLDER_ID_PROFILE: Guid = Guid {
    data1: 0x5e6c_858f,
    data2: 0x0e22,
    data3: 0x4760,
    data4: [0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73],
};

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
union IoStatusValue {
    status: i32,
    pointer: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    value: IoStatusValue,
    information: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[repr(C)]
struct FileIdInfo {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[repr(C)]
#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
struct FileDispositionInformation {
    delete_file: u8,
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
    fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
    fn LookupAccountSidW(
        system_name: *const u16,
        sid: *const c_void,
        name: *mut u16,
        name_size: *mut u32,
        domain: *mut u16,
        domain_size: *mut u32,
        sid_name_use: *mut i32,
    ) -> i32;
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
    fn GetSecurityInfo(
        handle: *mut c_void,
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
    fn GetAce(acl: *const Acl, index: u32, ace: *mut *mut c_void) -> i32;
    fn CreateWellKnownSid(
        sid_type: i32,
        domain_sid: *const c_void,
        sid: *mut c_void,
        sid_size: *mut u32,
    ) -> i32;
    fn EqualSid(first: *const c_void, second: *const c_void) -> i32;
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn LookupPrivilegeValueW(system_name: *const u16, name: *const u16, luid: *mut Luid) -> i32;
    fn AdjustTokenPrivileges(
        token: *mut c_void,
        disable_all_privileges: i32,
        new_state: *const TokenPrivileges,
        buffer_length: u32,
        previous_state: *mut TokenPrivileges,
        return_length: *mut u32,
    ) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        information_class: u32,
        information: *mut c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn GetLengthSid(sid: *const c_void) -> u32;
    fn CopySid(destination_length: u32, destination: *mut c_void, source: *const c_void) -> i32;
    fn GetSidSubAuthorityCount(sid: *const c_void) -> *mut u8;
    fn GetSidSubAuthority(sid: *const c_void, sub_authority: u32) -> *mut u32;
    fn DuplicateTokenEx(
        existing_token: *mut c_void,
        desired_access: u32,
        token_attributes: *const SecurityAttributes,
        impersonation_level: u32,
        token_type: u32,
        new_token: *mut *mut c_void,
    ) -> i32;
    #[cfg(test)]
    fn LogonUserW(
        username: *const u16,
        domain: *const u16,
        password: *const u16,
        logon_type: u32,
        provider: u32,
        token: *mut *mut c_void,
    ) -> i32;
    #[cfg(test)]
    fn ImpersonateLoggedOnUser(token: *mut c_void) -> i32;
    #[cfg(test)]
    fn RevertToSelf() -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteExW(execute_info: *mut ShellExecuteInfoW) -> i32;
    #[allow(dead_code)]
    fn SHGetKnownFolderPath(
        folder_id: *const Guid,
        flags: u32,
        token: *mut c_void,
        path: *mut *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, concurrency_model: u32) -> i32;
    fn CoUninitialize();
    #[allow(dead_code)]
    fn CoTaskMemFree(memory: *mut c_void);
}

pub(super) fn resolve_current_worker_principal() -> io::Result<WorkerPrincipal> {
    let sid = current_user_sid()?;
    principal_for_sid(&sid)
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn default_worker_root(
    scope: super::InstallationScope,
    principal: &WorkerPrincipal,
) -> io::Result<(PathBuf, super::WorkerRootCreationPolicy)> {
    validate_worker_root_principal(scope, principal)?;
    match scope {
        super::InstallationScope::System => Ok((
            PathBuf::from(r"C:\Styrn"),
            super::WorkerRootCreationPolicy::ExistingParent {
                allow_untrusted_parent_create: true,
            },
        )),
        super::InstallationScope::User => {
            let current = resolve_current_worker_principal()?;
            super::validate_user_scope_principal(principal, &current)?;
            let data = current_local_app_data()?;
            let profile = current_profile_directory()?;
            let creation_policy = if WindowsWorkerPath::parse(&data)?
                .has_component_prefix(&WindowsWorkerPath::parse(&profile)?)
            {
                super::WorkerRootCreationPolicy::CreateMissingFrom(profile)
            } else {
                super::WorkerRootCreationPolicy::ExistingParent {
                    allow_untrusted_parent_create: false,
                }
            };
            let root = data.join("Styrn");
            if !worker_root_path_is_normalized(&root) {
                return Err(invalid_data(
                    "Windows LocalAppData is not an exact normalized path",
                ));
            }
            Ok((root, creation_policy))
        }
    }
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn validate_worker_root_principal(
    scope: super::InstallationScope,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    verify_worker_principal(principal)?;
    if scope == super::InstallationScope::User {
        let current = resolve_current_worker_principal()?;
        super::validate_user_scope_principal(principal, &current)?;
    }
    Ok(())
}

fn revalidate_worker_root_principal(
    layout: &super::WorkerDirectoryLayout,
) -> io::Result<WorkerPrincipal> {
    #[cfg(test)]
    if let Some(revalidation) = &layout.principal_revalidation {
        let (resolved, current) = match revalidation {
            super::WorkerPrincipalRevalidationTest::Resolved { principal, current } => {
                (Ok(principal.clone()), current.as_ref())
            }
            super::WorkerPrincipalRevalidationTest::Deleted => (
                Err(io::Error::new(io::ErrorKind::NotFound, "worker deleted")),
                None,
            ),
        };
        return super::validate_revalidated_worker_principal(
            layout.scope,
            &layout.principal,
            resolved,
            current,
        );
    }
    let scope = layout.scope;
    let principal = &layout.principal;
    let sid = principal_sid(principal)?;
    let resolved = principal_for_sid(&sid);
    let current = if scope == super::InstallationScope::User {
        Some(resolve_current_worker_principal()?)
    } else {
        None
    };
    super::validate_revalidated_worker_principal(scope, principal, resolved, current.as_ref())
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn worker_root_path_is_normalized(path: &Path) -> bool {
    use std::path::{Component, Prefix};

    let mut components = path.components();
    if !matches!(
        components.next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
    ) || !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return false;
    }
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if !super::windows_worker_root_text_is_normalized(&units) {
        return false;
    }
    let terminated = units
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut full = vec![0_u16; 32_768];
    let length = unsafe {
        GetFullPathNameW(
            terminated.as_ptr(),
            full.len().try_into().unwrap_or(u32::MAX),
            full.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    length != 0
        && usize::try_from(length)
            .is_ok_and(|length| length < full.len() && full[..length] == units)
}

#[allow(dead_code)] // Reached through the deferred T0.14 action integration.
fn current_local_app_data() -> io::Result<PathBuf> {
    current_known_folder(&FOLDER_ID_LOCAL_APP_DATA, "LocalAppData")
}

#[allow(dead_code)] // Reached through the deferred T0.14 action integration.
fn current_profile_directory() -> io::Result<PathBuf> {
    current_known_folder(&FOLDER_ID_PROFILE, "profile")
}

#[allow(dead_code)] // Independent native expectation for the platform contract test.
#[cfg(test)]
pub(super) fn native_profile_data_root_for_test() -> io::Result<PathBuf> {
    current_known_folder(&FOLDER_ID_LOCAL_APP_DATA, "LocalAppData")
}

#[allow(dead_code)] // Reached through the deferred T0.14 action integration.
fn current_known_folder(folder: &Guid, label: &str) -> io::Result<PathBuf> {
    let mut raw_path = std::ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(folder, 0, std::ptr::null_mut(), &mut raw_path) };
    if status < 0 || raw_path.is_null() {
        return Err(io::Error::other(format!(
            "Windows could not resolve the current {label} folder"
        )));
    }
    let raw_path = CoTaskMemWideString(raw_path);
    let mut length = 0_usize;
    while length < 32_768 && unsafe { *raw_path.0.add(length) } != 0 {
        length += 1;
    }
    if length == 32_768 {
        return Err(invalid_data("Windows known-folder path is not terminated"));
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw_path.0, length)
    }));
    if !path.is_absolute() {
        return Err(invalid_data("Windows known-folder path is not absolute"));
    }
    Ok(path)
}

#[allow(dead_code)] // Consumed by the T0.14 setup action integration follow-up.
pub(super) fn create_worker_directory_layout(
    layout: &super::WorkerDirectoryLayout,
) -> io::Result<super::WorkerDirectoryCreation> {
    let root_path = WindowsWorkerPath::parse(layout.root())?;
    let (first_creatable, allow_untrusted_parent_create) = match &layout.creation_policy {
        super::WorkerRootCreationPolicy::ExistingParent {
            allow_untrusted_parent_create,
            ..
        } => (
            root_path
                .components
                .len()
                .checked_sub(1)
                .ok_or_else(|| invalid_data("worker root has no leaf component"))?,
            *allow_untrusted_parent_create,
        ),
        super::WorkerRootCreationPolicy::CreateMissingFrom(anchor) => {
            let anchor = WindowsWorkerPath::parse(anchor)?;
            if !root_path.has_component_prefix(&anchor)
                || root_path.components.len() == anchor.components.len()
            {
                return Err(permission_denied(
                    "worker standard root escapes its native profile anchor",
                ));
            }
            (anchor.components.len(), false)
        }
    };
    let security = WorkerCreationSecurity::new(&layout.principal)?;
    let lock_anchor = prepare_worker_lock_anchor(
        &root_path,
        first_creatable,
        allow_untrusted_parent_create,
        &security,
    )?;
    let lock_suffix = &root_path.components[first_creatable..];
    // The mutex is created before dedicated-owner privilege preflight. Its owner must therefore
    // be the current token principal, while SYSTEM and Administrators retain coordination access.
    let lock_security = WorkerCreationSecurity::new(&resolve_current_worker_principal()?)?;
    let creation_lock = WorkerLayoutLock::acquire(&lock_anchor, lock_suffix, &lock_security)?;
    let verified_principal = revalidate_worker_root_principal(layout)?;
    let security = WorkerCreationSecurity::new(&verified_principal)?;
    let restore_privilege = RestorePrivilegeGuard::enable_for_owner(&security.owner_sid)?;
    let prepared = prepare_worker_root(
        &root_path,
        first_creatable,
        allow_untrusted_parent_create,
        &security,
    )?;
    let result = create_worker_directory_layout_with_authority(
        layout,
        &root_path,
        prepared,
        security,
        creation_lock,
        lock_anchor,
    );
    let restore_result = restore_privilege.restore();
    restore_result?;
    result
}

fn create_worker_directory_layout_with_authority(
    layout: &super::WorkerDirectoryLayout,
    root_path: &WindowsWorkerPath,
    prepared: PreparedWorkerRoot,
    security: WorkerCreationSecurity,
    creation_lock: WorkerLayoutLock,
    lock_anchor: std::fs::File,
) -> io::Result<super::WorkerDirectoryCreation> {
    let mut directory = prepared.directory;
    let mut root_disposition = prepared.root_disposition;
    for (index, component) in root_path.components[prepared.next_component..]
        .iter()
        .enumerate()
    {
        let component_index = prepared.next_component + index;
        let is_root = component_index + 1 == root_path.components.len();
        let opened =
            open_or_create_worker_directory_at(&directory, component, true, &security, is_root)?;
        if is_root {
            root_disposition = Some(opened.disposition);
        }
        directory = opened.directory;
    }
    let root_identity = worker_directory_identity(&directory)?;
    let root_observation = super::WorkerDirectoryNodeObservation::new(
        layout.root().to_path_buf(),
        root_disposition.expect("the normalized worker root has a leaf component"),
        root_identity,
    );

    let mut children = Vec::with_capacity(super::WorkerDirectoryLayout::child_names().len());
    for name in super::WorkerDirectoryLayout::child_names() {
        let name = name.encode_utf16().collect::<Vec<_>>();
        match open_worker_directory_at_with_security(&directory, &name, true) {
            Ok(child) => {
                verify_worker_directory_security(&child, &security.owner_sid)?;
                children.push(Some(OpenedWorkerDirectory {
                    directory: child,
                    disposition: super::WorkerDirectoryNodeDisposition::Existing,
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                children.push(None);
            }
            Err(error) => return Err(error),
        }
    }
    for (index, child) in children.iter_mut().enumerate() {
        if child.is_none() {
            let name = super::WorkerDirectoryLayout::child_names()[index]
                .encode_utf16()
                .collect::<Vec<_>>();
            *child = Some(open_or_create_worker_directory_at(
                &directory, &name, true, &security, true,
            )?);
        }
    }

    if worker_directory_identity(&directory)? != root_identity {
        return Err(permission_denied(
            "worker root identity changed during layout creation",
        ));
    }
    let reopened_root = open_existing_worker_path(root_path)?;
    if worker_directory_identity(&reopened_root)? != root_identity {
        return Err(permission_denied(
            "worker root pathname changed during layout creation",
        ));
    }
    let mut child_observations = Vec::with_capacity(children.len());
    let mut child_handles = Vec::with_capacity(children.len());
    for (name, child) in super::WorkerDirectoryLayout::child_names()
        .into_iter()
        .zip(children)
    {
        let child = child.expect("every fixed worker child was opened or created");
        let name_units = name.encode_utf16().collect::<Vec<_>>();
        let reopened = open_worker_directory_at(&directory, &name_units)?;
        let identity = worker_directory_identity(&child.directory)?;
        if worker_directory_identity(&reopened)? != identity {
            return Err(permission_denied(
                "worker layout child identity changed during creation",
            ));
        }
        child_observations.push(super::WorkerDirectoryNodeObservation::new(
            layout.root().join(name),
            child.disposition,
            identity,
        ));
        child_handles.push(child.directory);
    }
    let [repos, jobs, cache, artifacts, logs] = child_handles
        .try_into()
        .unwrap_or_else(|_| unreachable!("the worker layout always has exactly five children"));
    let lease = WorkerDirectoryLease {
        _creation_lock: creation_lock,
        _lock_anchor: lock_anchor,
        nodes: [directory, repos, jobs, cache, artifacts, logs],
        owner_sid: security.owner_sid.clone(),
    };
    Ok(super::WorkerDirectoryCreation::new(
        root_observation,
        child_observations
            .try_into()
            .unwrap_or_else(|_| unreachable!("the worker layout always has exactly five children")),
        lease,
    ))
}

struct PreparedWorkerRoot {
    directory: std::fs::File,
    next_component: usize,
    root_disposition: Option<super::WorkerDirectoryNodeDisposition>,
}

struct OpenedWorkerDirectory {
    directory: std::fs::File,
    disposition: super::WorkerDirectoryNodeDisposition,
}

pub(super) struct WorkerDirectoryLease {
    _creation_lock: WorkerLayoutLock,
    _lock_anchor: std::fs::File,
    nodes: [std::fs::File; 6],
    owner_sid: Vec<u8>,
}

pub(super) fn reverify_worker_directory_lease(
    lease: &WorkerDirectoryLease,
    observations: &[super::WorkerDirectoryNodeObservation; 6],
) -> io::Result<()> {
    for (directory, observation) in lease.nodes.iter().zip(observations) {
        verify_worker_directory_security(directory, &lease.owner_sid)?;
        if worker_directory_identity(directory)? != observation.identity() {
            return Err(permission_denied(
                "retained worker directory identity changed before release",
            ));
        }
        let path = WindowsWorkerPath::parse(observation.path())?;
        let reopened = open_existing_worker_path(&path)?;
        if worker_directory_identity(&reopened)? != observation.identity() {
            return Err(permission_denied(
                "worker directory path changed before retained evidence release",
            ));
        }
    }
    Ok(())
}

pub(super) fn retire_worker_directory_authority(_lease: &WorkerDirectoryLease) -> io::Result<()> {
    Ok(())
}

fn prepare_worker_lock_anchor(
    path: &WindowsWorkerPath,
    anchor_components: usize,
    allow_untrusted_parent_create: bool,
    security: &WorkerCreationSecurity,
) -> io::Result<std::fs::File> {
    let mut directory = open_worker_volume_root(&path.volume_root, true)?;
    verify_trusted_worker_ancestor(
        &directory,
        &security.owner_sid,
        anchor_components != 0 || allow_untrusted_parent_create,
    )?;
    for (index, component) in path.components[..anchor_components].iter().enumerate() {
        let opened = open_worker_directory_at_with_security(&directory, component, true)?;
        verify_trusted_worker_ancestor(
            &opened,
            &security.owner_sid,
            index + 1 < anchor_components,
        )?;
        directory = opened;
    }
    Ok(directory)
}

fn prepare_worker_root(
    path: &WindowsWorkerPath,
    first_creatable: usize,
    allow_untrusted_parent_create: bool,
    security: &WorkerCreationSecurity,
) -> io::Result<PreparedWorkerRoot> {
    let mut directory = open_worker_volume_root(&path.volume_root, true)?;
    verify_trusted_worker_ancestor(
        &directory,
        &security.owner_sid,
        first_creatable != 0 || allow_untrusted_parent_create,
    )?;
    for (index, component) in path.components.iter().enumerate() {
        match open_worker_directory_at_with_security(&directory, component, true) {
            Ok(opened) => {
                if index + 1 == path.components.len() {
                    verify_worker_directory_security(&opened, &security.owner_sid)?;
                } else {
                    verify_trusted_worker_ancestor(
                        &opened,
                        &security.owner_sid,
                        index + 1 < first_creatable,
                    )?;
                }
                directory = opened;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && index >= first_creatable => {
                verify_trusted_worker_ancestor(
                    &directory,
                    &security.owner_sid,
                    allow_untrusted_parent_create,
                )?;
                return Ok(PreparedWorkerRoot {
                    directory,
                    next_component: index,
                    root_disposition: None,
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(PreparedWorkerRoot {
        directory,
        next_component: path.components.len(),
        root_disposition: Some(super::WorkerDirectoryNodeDisposition::Existing),
    })
}

struct WindowsWorkerPath {
    volume_root: Vec<u16>,
    components: Vec<Vec<u16>>,
}

impl WindowsWorkerPath {
    fn parse(path: &Path) -> io::Result<Self> {
        if !worker_root_path_is_normalized(path) {
            return Err(invalid_data("worker directory path is not normalized"));
        }
        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        let volume_root = units[..3]
            .iter()
            .copied()
            .chain(std::iter::once(0))
            .collect();
        let components = units[3..]
            .split(|unit| *unit == b'\\' as u16)
            .map(<[u16]>::to_vec)
            .collect();
        Ok(Self {
            volume_root,
            components,
        })
    }

    fn has_component_prefix(&self, prefix: &Self) -> bool {
        u8::try_from(self.volume_root[0]).is_ok_and(|left| {
            u8::try_from(prefix.volume_root[0]).is_ok_and(|right| left.eq_ignore_ascii_case(&right))
        }) && self.volume_root[1] == prefix.volume_root[1]
            && self.components.len() >= prefix.components.len()
            && self
                .components
                .iter()
                .zip(&prefix.components)
                .all(|(left, right)| windows_components_equal(left, right))
    }
}

fn windows_components_equal(left: &[u16], right: &[u16]) -> bool {
    let (Ok(left_length), Ok(right_length)) =
        (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    (unsafe { CompareStringOrdinal(left.as_ptr(), left_length, right.as_ptr(), right_length, 1) })
        == CSTR_EQUAL
}

struct WorkerCreationSecurity {
    descriptor: LocalAllocation,
    owner_sid: Vec<u8>,
}

impl WorkerCreationSecurity {
    fn new(principal: &WorkerPrincipal) -> io::Result<Self> {
        let owner_sid = principal_sid(principal)?;
        let owner = sid_to_string(owner_sid.as_ptr().cast())?;
        let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
        let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
        let owner_is_management =
            unsafe { EqualSid(owner_sid.as_ptr().cast(), system.as_ptr().cast()) } != 0
                || unsafe { EqualSid(owner_sid.as_ptr().cast(), administrators.as_ptr().cast()) }
                    != 0;
        let sddl = if owner_is_management {
            wide(&format!("O:{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"))
        } else {
            wide(&format!(
                "O:{owner}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{owner})"
            ))
        };
        let mut descriptor = std::ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor: LocalAllocation(descriptor),
            owner_sid,
        })
    }
}

struct RestorePrivilegeGuard {
    token: Option<OwnedHandle>,
    previous: TokenPrivileges,
    restored: bool,
}

impl RestorePrivilegeGuard {
    fn enable_for_owner(owner_sid: &[u8]) -> io::Result<Self> {
        let current_sid = current_user_sid()?;
        let owner_matches_current =
            unsafe { EqualSid(owner_sid.as_ptr().cast(), current_sid.as_ptr().cast()) } != 0;
        if owner_matches_current {
            return Ok(Self {
                token: None,
                previous: empty_token_privileges(),
                restored: true,
            });
        }

        let mut token = std::ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                &mut token,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        let mut luid = Luid {
            low_part: 0,
            high_part: 0,
        };
        let privilege_name = wide("SeRestorePrivilege");
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), privilege_name.as_ptr(), &mut luid) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let requested = TokenPrivileges {
            privilege_count: 1,
            privileges: [LuidAndAttributes {
                luid,
                attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = empty_token_privileges();
        let mut previous_length = 0;
        unsafe { SetLastError(0) };
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &requested,
                std::mem::size_of::<TokenPrivileges>() as u32,
                &mut previous,
                &mut previous_length,
            )
        } != 0;
        let last_error = unsafe { GetLastError() };
        let guard = Self {
            token: Some(token),
            previous,
            restored: false,
        };
        super::validate_windows_restore_privilege_result(
            owner_matches_current,
            adjusted,
            last_error,
        )?;
        if previous_length > std::mem::size_of::<TokenPrivileges>() as u32 {
            return Err(invalid_data(
                "Windows returned an oversized restore-privilege state",
            ));
        }
        Ok(guard)
    }

    fn restore(mut self) -> io::Result<()> {
        self.restore_inner()
    }

    fn restore_inner(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        let token = self
            .token
            .as_ref()
            .expect("an enabled privilege retains its process token");
        if unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &self.previous,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for RestorePrivilegeGuard {
    fn drop(&mut self) {
        let _ = self.restore_inner();
    }
}

fn empty_token_privileges() -> TokenPrivileges {
    TokenPrivileges {
        privilege_count: 0,
        privileges: [LuidAndAttributes {
            luid: Luid {
                low_part: 0,
                high_part: 0,
            },
            attributes: 0,
        }],
    }
}

struct WorkerLayoutLock {
    handle: OwnedHandle,
}

impl WorkerLayoutLock {
    fn acquire(
        canonical_parent: &std::fs::File,
        missing_suffix: &[Vec<u16>],
        security: &WorkerCreationSecurity,
    ) -> io::Result<Self> {
        use std::fmt::Write;

        let bytes = worker_layout_lock_key(canonical_parent, missing_suffix)?;
        let digest = Sha256::digest(bytes);
        let mut name = String::from(r"Global\Styrn.WorkerLayout.");
        for byte in digest {
            write!(&mut name, "{byte:02x}").expect("writing to a String cannot fail");
        }
        let name = wide(&name);
        let attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: security.descriptor.0,
            inherit_handle: 0,
        };
        let handle = unsafe { CreateMutexW(&attributes, 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = OwnedHandle(handle);
        let result = unsafe { WaitForSingleObject(handle.0, INFINITE) };
        if !matches!(result, WAIT_OBJECT_0 | WAIT_ABANDONED_0) {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }
}

fn worker_layout_lock_key(
    canonical_parent: &std::fs::File,
    missing_suffix: &[Vec<u16>],
) -> io::Result<Vec<u8>> {
    let identity = worker_directory_identity(canonical_parent)?;
    let normalized_suffix = normalized_worker_lock_suffix(canonical_parent, missing_suffix)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&identity.volume.to_le_bytes());
    bytes.extend_from_slice(&identity.file_id);
    for component in normalized_suffix {
        let mut folded = component;
        let folded_length = u32::try_from(folded.len())
            .map_err(|_| invalid_data("worker root path is too long for a coordination lock"))?;
        if folded_length > 0 && unsafe { CharUpperBuffW(folded.as_mut_ptr(), folded_length) } == 0 {
            return Err(io::Error::last_os_error());
        }
        bytes.extend_from_slice(&folded_length.to_le_bytes());
        for unit in folded {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    Ok(bytes)
}

fn normalized_worker_lock_suffix(
    canonical_parent: &std::fs::File,
    logical_suffix: &[Vec<u16>],
) -> io::Result<Vec<Vec<u16>>> {
    let mut normalized = Vec::with_capacity(logical_suffix.len());
    let mut directory = canonical_parent.try_clone()?;
    let mut existing = true;
    for component in logical_suffix {
        if existing {
            match open_worker_directory_at(&directory, component) {
                Ok(opened) => {
                    normalized.push(final_worker_component_name(&opened)?);
                    directory = opened;
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => existing = false,
                Err(error) => return Err(error),
            }
        }
        normalized.push(component.clone());
    }
    Ok(normalized)
}

fn final_worker_component_name(directory: &std::fs::File) -> io::Result<Vec<u16>> {
    use std::os::windows::io::AsRawHandle;

    let required =
        unsafe { GetFinalPathNameByHandleW(directory.as_raw_handle(), std::ptr::null_mut(), 0, 0) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0_u16; required as usize];
    let length = unsafe {
        GetFinalPathNameByHandleW(directory.as_raw_handle(), path.as_mut_ptr(), required, 0)
    };
    if length == 0 || length >= required {
        return Err(io::Error::last_os_error());
    }
    path.truncate(length as usize);
    let component = path
        .rsplit(|unit| *unit == b'\\' as u16)
        .next()
        .filter(|component| !component.is_empty())
        .ok_or_else(|| invalid_data("Windows returned no final worker path component"))?;
    Ok(component.to_vec())
}

impl Drop for WorkerLayoutLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle.0);
        }
    }
}

fn open_worker_volume_root(volume_root: &[u16], read_security: bool) -> io::Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;

    let handle = unsafe {
        CreateFileW(
            volume_root.as_ptr(),
            FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | if read_security { READ_CONTROL } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { std::fs::File::from_raw_handle(handle) };
    worker_directory_identity(&directory)?;
    Ok(directory)
}

fn open_existing_worker_path(path: &WindowsWorkerPath) -> io::Result<std::fs::File> {
    let mut directory = open_worker_volume_root(&path.volume_root, false)?;
    for component in &path.components {
        directory = open_worker_directory_at(&directory, component)?;
    }
    Ok(directory)
}

fn open_or_create_worker_directory_at(
    parent: &std::fs::File,
    name: &[u16],
    may_create: bool,
    security: &WorkerCreationSecurity,
    existing_must_be_canonical: bool,
) -> io::Result<OpenedWorkerDirectory> {
    match open_worker_directory_at_with_security(parent, name, true) {
        Ok(directory) => {
            verify_existing_worker_directory(
                &directory,
                &security.owner_sid,
                existing_must_be_canonical,
            )?;
            return Ok(OpenedWorkerDirectory {
                directory,
                disposition: super::WorkerDirectoryNodeDisposition::Existing,
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && may_create => {}
        Err(error) => return Err(error),
    }
    match nt_open_worker_directory_at(parent, name, FILE_CREATE, security.descriptor.0, false) {
        Ok(directory) => {
            verify_worker_directory_security(&directory, &security.owner_sid)?;
            Ok(OpenedWorkerDirectory {
                directory,
                disposition: super::WorkerDirectoryNodeDisposition::Created,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let directory = open_worker_directory_at_with_security(parent, name, true)?;
            verify_existing_worker_directory(
                &directory,
                &security.owner_sid,
                existing_must_be_canonical,
            )?;
            Ok(OpenedWorkerDirectory {
                directory,
                disposition: super::WorkerDirectoryNodeDisposition::Existing,
            })
        }
        Err(error) => Err(error),
    }
}

fn verify_existing_worker_directory(
    directory: &std::fs::File,
    expected_owner: &[u8],
    must_be_canonical: bool,
) -> io::Result<()> {
    if must_be_canonical {
        verify_worker_directory_security(directory, expected_owner)
    } else {
        verify_trusted_worker_ancestor(directory, expected_owner, false)
    }
}

fn open_worker_directory_at(parent: &std::fs::File, name: &[u16]) -> io::Result<std::fs::File> {
    open_worker_directory_at_with_security(parent, name, false)
}

fn open_worker_directory_at_with_security(
    parent: &std::fs::File,
    name: &[u16],
    read_security: bool,
) -> io::Result<std::fs::File> {
    nt_open_worker_directory_at(parent, name, FILE_OPEN, std::ptr::null_mut(), read_security)
}

fn nt_open_worker_directory_at(
    parent: &std::fs::File,
    name: &[u16],
    disposition: u32,
    security_descriptor: *mut c_void,
    read_security: bool,
) -> io::Result<std::fs::File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    let byte_length = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| invalid_data("worker directory component is too long"))?;
    let mut name = name.to_vec();
    let mut unicode = UnicodeString {
        length: byte_length,
        maximum_length: byte_length,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor,
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut status_block = unsafe { std::mem::zeroed::<IoStatusBlock>() };
    let mut handle = std::ptr::null_mut();
    let desired_access = FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if disposition == FILE_CREATE || read_security {
            READ_CONTROL
        } else {
            0
        };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &mut attributes,
            &mut status_block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            disposition,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        let error = unsafe { RtlNtStatusToDosError(status) };
        return Err(worker_directory_windows_error(
            io::Error::from_raw_os_error(error as i32),
        ));
    }
    if handle.is_null() {
        return Err(invalid_data(
            "Windows opened a null worker directory handle",
        ));
    }
    let directory = unsafe { std::fs::File::from_raw_handle(handle) };
    worker_directory_identity(&directory)?;
    Ok(directory)
}

fn worker_directory_windows_error(error: io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(267 | 1920 | 4390 | 4391 | 4392 | 4393 | 4394) => permission_denied(
            "worker layout ancestry contains a reparse point or non-directory component",
        ),
        _ => error,
    }
}

fn worker_directory_identity(
    directory: &std::fs::File,
) -> io::Result<super::WorkerDirectoryIdentity> {
    use std::os::windows::io::AsRawHandle;

    let mut attributes = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    if unsafe { GetFileInformationByHandle(directory.as_raw_handle(), &mut attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if attributes.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || attributes.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(permission_denied(
            "worker layout path is a reparse point or non-directory",
        ));
    }
    let mut identity = unsafe { std::mem::zeroed::<FileIdInfo>() };
    if unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            std::ptr::addr_of_mut!(identity).cast(),
            std::mem::size_of::<FileIdInfo>()
                .try_into()
                .map_err(|_| invalid_data("Windows FILE_ID_INFO size is invalid"))?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(super::WorkerDirectoryIdentity::from_windows(
        identity.volume_serial_number,
        identity.file_id,
    ))
}

fn verify_trusted_worker_ancestor(
    directory: &std::fs::File,
    creation_authority: &[u8],
    allow_untrusted_create_child: bool,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            directory.as_raw_handle(),
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
    let _descriptor = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(permission_denied(
            "system worker root ancestor has an incomplete DACL",
        ));
    }
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let trusted_installer = lookup_account_sid("NT SERVICE\\TrustedInstaller")?;
    let owner_is_trusted = unsafe { EqualSid(owner, creation_authority.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, system.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, administrators.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, trusted_installer.as_ptr().cast()) } != 0;
    let entries = inspect_aces(
        dacl,
        &system,
        &administrators,
        &trusted_installer,
        creation_authority,
    )?;
    validate_worker_ancestor_acl(owner_is_trusted, &entries, allow_untrusted_create_child)
}

fn validate_worker_ancestor_acl(
    owner_is_trusted: bool,
    entries: &[AceInspection],
    allow_untrusted_create_child: bool,
) -> io::Result<()> {
    if !owner_is_trusted {
        return Err(permission_denied(
            "system worker root ancestor is owned by an untrusted principal",
        ));
    }
    if entries.iter().any(|entry| {
        if !entry.allowed
            || entry.flags & INHERIT_ONLY_ACE != 0
            || matches!(
                entry.principal,
                Principal::System
                    | Principal::Administrators
                    | Principal::TrustedInstaller
                    | Principal::Worker
            )
        {
            return false;
        }
        let create_child = entry.mask & 0x0000_0004 != 0;
        entry.mask & (PARENT_TAKEOVER_ACCESS | 0x0000_0002) != 0
            || (create_child && !allow_untrusted_create_child)
    }) {
        return Err(permission_denied(
            "system worker root ancestor is writable by an untrusted principal",
        ));
    }
    Ok(())
}

fn verify_worker_directory_security(
    directory: &std::fs::File,
    expected_owner: &[u8],
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            directory.as_raw_handle(),
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
    if owner.is_null() || dacl.is_null() || descriptor.0.is_null() {
        return Err(permission_denied(
            "new worker directory security descriptor is incomplete",
        ));
    }
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let owner_matches = unsafe { EqualSid(owner, expected_owner.as_ptr().cast()) } != 0;
    let owner_is_management =
        unsafe { EqualSid(expected_owner.as_ptr().cast(), system.as_ptr().cast()) } != 0
            || unsafe {
                EqualSid(
                    expected_owner.as_ptr().cast(),
                    administrators.as_ptr().cast(),
                )
            } != 0;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let entries = inspect_aces(dacl, &system, &administrators, &system, expected_owner)?;
    validate_worker_creation_acl(
        &AclInspection {
            owner_matches_policy: owner_matches,
            dacl_is_protected: control & SE_DACL_PROTECTED != 0,
            entries,
        },
        owner_is_management,
    )
}

fn validate_worker_creation_acl(
    inspection: &AclInspection,
    owner_is_management: bool,
) -> io::Result<()> {
    if !inspection.owner_matches_policy || !inspection.dacl_is_protected {
        return Err(permission_denied(
            "new worker directory owner or DACL protection is invalid",
        ));
    }
    let inherited_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    let mut expected = vec![
        AceInspection {
            principal: Principal::System,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        },
        AceInspection {
            principal: Principal::Administrators,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        },
    ];
    if !owner_is_management {
        expected.push(AceInspection {
            principal: Principal::Worker,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        });
    }
    if inspection.entries.len() != expected.len()
        || expected
            .iter()
            .any(|entry| !inspection.entries.contains(entry))
    {
        return Err(permission_denied(
            "new worker directory DACL grants unexpected principals or access masks",
        ));
    }
    Ok(())
}

#[allow(dead_code)] // Reached through the deferred T0.14 action integration.
struct CoTaskMemWideString(*mut u16);

impl Drop for CoTaskMemWideString {
    fn drop(&mut self) {
        unsafe { CoTaskMemFree(self.0.cast()) };
    }
}

#[allow(dead_code)]
pub(super) struct UserExecutionToken {
    handle: OwnedHandle,
    principal: WorkerPrincipal,
}

#[cfg(test)]
pub(super) fn test_user_execution_token(_principal: &WorkerPrincipal) -> UserExecutionToken {
    let mut token = std::ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0,
        "the current Windows process token must be available to tests"
    );
    UserExecutionToken {
        handle: OwnedHandle(token),
        principal: resolve_current_worker_principal().unwrap(),
    }
}

pub(super) fn capture_setup_execution_context() -> io::Result<SetupExecutionContext> {
    let current = open_current_process_token()?;
    let current_posture = inspect_token_posture(&current)?;
    let linked = match current_posture.elevation_type {
        WindowsTokenElevationType::Default => None,
        WindowsTokenElevationType::Full | WindowsTokenElevationType::Limited => {
            Some(linked_token(&current)?)
        }
    };
    let linked_posture = linked.as_ref().map(inspect_token_posture).transpose()?;
    let choice = select_windows_user_token(current_posture, linked_posture)?;
    let source = match choice {
        WindowsUserTokenChoice::Current => &current,
        WindowsUserTokenChoice::LinkedLimited => linked.as_ref().ok_or_else(|| {
            permission_denied("Windows elevated token has no linked limited user token")
        })?,
    };

    let expected_posture = match choice {
        WindowsUserTokenChoice::Current => current_posture,
        WindowsUserTokenChoice::LinkedLimited => linked_posture.ok_or_else(|| {
            permission_denied("Windows elevated token has no linked limited user posture")
        })?,
    };
    let primary = duplicate_primary_token(source)?;
    if inspect_token_posture(&primary)? != expected_posture {
        return Err(permission_denied(
            "Windows user token posture changed while it was captured",
        ));
    }
    let current_sid = token_user_sid(&current)?;
    let user_sid = token_user_sid(&primary)?;
    if unsafe { EqualSid(current_sid.as_ptr().cast(), user_sid.as_ptr().cast()) } == 0 {
        return Err(permission_denied(
            "Windows linked token belongs to a different user",
        ));
    }
    let principal = principal_for_sid(&user_sid)?;
    let token = UserExecutionToken {
        handle: primary,
        principal: principal.clone(),
    };
    let privilege = if choice == WindowsUserTokenChoice::LinkedLimited {
        SetupHostPrivilege::Administrator
    } else {
        SetupHostPrivilege::Ordinary
    };
    Ok(SetupExecutionContext::new(privilege, principal, token))
}

pub(super) fn invoke_setup_authorization(
    executable: &Path,
    request_path: &Path,
    request_digest: &str,
) -> io::Result<std::process::ExitStatus> {
    let current = std::env::current_exe()?;
    let executable = hold_verified_authorization_executable(executable)?;
    let arguments = super::validated_privileged_phase_arguments(
        &executable.path,
        request_path,
        request_digest,
        &current,
    )?;
    let mut parameters = Vec::<u16>::new();
    for argument in arguments {
        if !parameters.is_empty() {
            parameters.push(u16::from(b' '));
        }
        parameters.extend(super::windows_quote_command_argument(
            &argument.encode_wide().collect::<Vec<_>>(),
        )?);
    }
    parameters.push(0);
    let verb = wide("runas");
    let file = wide_os(&executable.path);
    let directory = wide_os(
        executable
            .path
            .parent()
            .ok_or_else(|| invalid_data("setup authorization executable has no parent"))?,
    );
    let (_, launch_information) = open_authorization_executable_handle(&executable.path)?;
    if file_identity(&launch_information) != executable.identity {
        return Err(permission_denied(
            "setup authorization executable identity changed before launch",
        ));
    }
    let _com = initialize_com_for_shell()?;
    let mut execute_info = ShellExecuteInfoW {
        size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
        mask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        window: std::ptr::null_mut(),
        verb: verb.as_ptr(),
        file: file.as_ptr(),
        parameters: parameters.as_ptr(),
        directory: directory.as_ptr(),
        show: SW_SHOWNORMAL,
        instance: std::ptr::null_mut(),
        id_list: std::ptr::null_mut(),
        class: std::ptr::null(),
        class_key: std::ptr::null_mut(),
        hot_key: 0,
        icon_or_monitor: std::ptr::null_mut(),
        process: std::ptr::null_mut(),
    };
    if unsafe { ShellExecuteExW(&mut execute_info) } == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(1223) {
            Err(permission_denied(
                "native Windows setup authorization was declined",
            ))
        } else {
            Err(error)
        };
    }
    if execute_info.process as usize <= 32 {
        return Err(permission_denied(
            "native Windows authorization did not return a child process",
        ));
    }
    let process = OwnedHandle(execute_info.process);
    if unsafe { WaitForSingleObject(process.0, INFINITE) } != WAIT_OBJECT_0 {
        return Err(io::Error::last_os_error());
    }
    let mut exit_code = 0;
    if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
        return Err(io::Error::last_os_error());
    }
    use std::os::windows::process::ExitStatusExt;
    Ok(std::process::ExitStatus::from_raw(exit_code))
}

fn initialize_com_for_shell() -> io::Result<ComInitialization> {
    let status = unsafe {
        CoInitializeEx(
            std::ptr::null_mut(),
            COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
        )
    };
    if status >= 0 {
        Ok(ComInitialization { owns_call: true })
    } else if status == RPC_E_CHANGED_MODE {
        Ok(ComInitialization { owns_call: false })
    } else {
        Err(io::Error::other(
            "Windows could not initialize COM for native setup authorization",
        ))
    }
}

struct ComInitialization {
    owns_call: bool,
}

impl Drop for ComInitialization {
    fn drop(&mut self) {
        if self.owns_call {
            unsafe { CoUninitialize() };
        }
    }
}

pub(super) fn verify_setup_authorization_executable(
    executable: &Path,
) -> io::Result<std::path::PathBuf> {
    Ok(hold_verified_authorization_executable(executable)?.path)
}

struct VerifiedAuthorizationExecutable {
    path: std::path::PathBuf,
    _file: std::fs::File,
    identity: PrivateFileIdentity,
}

fn hold_verified_authorization_executable(
    executable: &Path,
) -> io::Result<VerifiedAuthorizationExecutable> {
    use std::path::{Component, Prefix};

    let executable = std::fs::canonicalize(executable)?;
    if !matches!(
        executable.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    ) {
        return Err(permission_denied(
            "setup authorization executable must use a local drive path",
        ));
    }
    if executable != std::fs::canonicalize(std::env::current_exe()?)? {
        return Err(permission_denied(
            "setup authorization executable is not the current binary",
        ));
    }
    let worker = resolve_current_worker_principal()?;
    let (file, information) = open_authorization_executable_handle(&executable)?;
    inspect_authorization_executable_acl(&file, &worker)?;
    let mut current = executable.parent();
    while let Some(ancestor) = current {
        require_kind(ancestor, true)?;
        inspect_authorization_ancestor_acl(ancestor, &worker)?;
        current = ancestor.parent();
    }
    if executable != std::fs::canonicalize(std::env::current_exe()?)? {
        return Err(permission_denied(
            "setup authorization executable changed during verification",
        ));
    }
    Ok(VerifiedAuthorizationExecutable {
        path: executable,
        _file: file,
        identity: file_identity(&information),
    })
}

pub(super) fn run_user_phase(
    token: &UserExecutionToken,
    request: &[u8],
) -> io::Result<std::process::ExitStatus> {
    if request.len() > 64 * 1024 {
        return Err(invalid_data("setup user-phase request is too large"));
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "native Windows user execution for {} is not implemented",
            token.principal.name()
        ),
    ))
}

fn open_current_process_token() -> io::Result<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(token))
}

fn duplicate_primary_token(source: &OwnedHandle) -> io::Result<OwnedHandle> {
    let mut token = std::ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            source.0,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            std::ptr::null(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(OwnedHandle(token))
}

fn linked_token(token: &OwnedHandle) -> io::Result<OwnedHandle> {
    let information = token_information(token, TOKEN_LINKED_TOKEN_CLASS)?;
    if information.byte_len < std::mem::size_of::<TokenLinkedToken>() {
        return Err(invalid_data(
            "Windows linked-token information is truncated",
        ));
    }
    let linked = unsafe { *information.as_ptr().cast::<TokenLinkedToken>() };
    if linked.linked_token.is_null() {
        return Err(permission_denied(
            "Windows token has no usable linked user token",
        ));
    }
    Ok(OwnedHandle(linked.linked_token))
}

fn inspect_token_posture(token: &OwnedHandle) -> io::Result<WindowsTokenPosture> {
    let elevation = token_information(token, TOKEN_ELEVATION_TYPE_CLASS)?;
    if elevation.byte_len < std::mem::size_of::<u32>() {
        return Err(invalid_data(
            "Windows token elevation information is truncated",
        ));
    }
    let elevation_type = unsafe { *elevation.as_ptr().cast::<u32>() };

    let integrity = token_information(token, TOKEN_INTEGRITY_LEVEL_CLASS)?;
    if integrity.byte_len < std::mem::size_of::<TokenMandatoryLabel>() {
        return Err(invalid_data(
            "Windows token integrity information is truncated",
        ));
    }
    let label = unsafe { *integrity.as_ptr().cast::<TokenMandatoryLabel>() };
    let integrity_rid = sid_last_sub_authority(label.label.sid)?;

    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let groups = token_information(token, TOKEN_GROUPS_CLASS)?;
    if groups.byte_len < std::mem::size_of::<TokenGroups>() {
        return Err(invalid_data("Windows token group information is truncated"));
    }
    let groups_ptr = groups.as_ptr().cast::<TokenGroups>();
    let count = unsafe { (*groups_ptr).group_count as usize };
    let groups_offset = std::mem::offset_of!(TokenGroups, groups);
    let available =
        groups.byte_len.saturating_sub(groups_offset) / std::mem::size_of::<SidAndAttributes>();
    if count > available {
        return Err(invalid_data("Windows token group count exceeds its buffer"));
    }
    let first = unsafe { std::ptr::addr_of!((*groups_ptr).groups).cast::<SidAndAttributes>() };
    let mut admin_attributes = None;
    for index in 0..count {
        let group = unsafe { *first.add(index) };
        if group.sid.is_null() {
            return Err(invalid_data("Windows token contains a null group SID"));
        }
        if unsafe { EqualSid(group.sid, administrators.as_ptr().cast()) } != 0
            && admin_attributes.replace(group.attributes).is_some()
        {
            return Err(invalid_data(
                "Windows token repeats the Administrators group SID",
            ));
        }
    }
    windows_token_posture_from_native(elevation_type, integrity_rid, admin_attributes)
}

fn sid_last_sub_authority(sid: *const c_void) -> io::Result<u32> {
    if sid.is_null() {
        return Err(invalid_data("Windows token contains a null integrity SID"));
    }
    let count = unsafe { GetSidSubAuthorityCount(sid) };
    if count.is_null() || unsafe { *count } == 0 {
        return Err(invalid_data("Windows integrity SID has no sub-authority"));
    }
    let value = unsafe { GetSidSubAuthority(sid, u32::from(*count) - 1) };
    if value.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { *value })
}

struct TokenInformation {
    words: Vec<usize>,
    byte_len: usize,
}

impl TokenInformation {
    fn as_ptr(&self) -> *const usize {
        self.words.as_ptr()
    }
}

fn token_information(token: &OwnedHandle, class: u32) -> io::Result<TokenInformation> {
    let mut required = 0;
    let result =
        unsafe { GetTokenInformation(token.0, class, std::ptr::null_mut(), 0, &mut required) };
    if result != 0 || required == 0 {
        return Err(invalid_data(
            "Windows returned an invalid token-information size",
        ));
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(io::Error::last_os_error());
    }
    let word_size = std::mem::size_of::<usize>();
    let word_count = (required as usize).div_ceil(word_size);
    let mut words = vec![0_usize; word_count];
    let capacity = words.len() * word_size;
    if unsafe {
        GetTokenInformation(
            token.0,
            class,
            words.as_mut_ptr().cast(),
            capacity
                .try_into()
                .map_err(|_| invalid_data("Windows token information is too large"))?,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if required as usize > capacity {
        return Err(invalid_data(
            "Windows token information grew while it was read",
        ));
    }
    Ok(TokenInformation {
        words,
        byte_len: required as usize,
    })
}

fn token_user_sid(token: &OwnedHandle) -> io::Result<Vec<u8>> {
    let information = token_information(token, TOKEN_USER_CLASS)?;
    if information.byte_len < std::mem::size_of::<TokenUser>() {
        return Err(invalid_data("Windows token user information is truncated"));
    }
    let token_user = unsafe { *information.as_ptr().cast::<TokenUser>() };
    if token_user.user.sid.is_null() {
        return Err(invalid_data("Windows token contains a null user SID"));
    }
    let sid_length = unsafe { GetLengthSid(token_user.user.sid) };
    if sid_length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0_u8; sid_length as usize];
    if unsafe {
        CopySid(
            sid_length,
            sid.as_mut_ptr().cast(),
            token_user.user.sid.cast_const(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

#[allow(dead_code)] // Explicit system-account selection is exercised by environmental gates.
pub(super) fn resolve_named_worker_principal(name: &str) -> io::Result<WorkerPrincipal> {
    // This is an explicit setup/test selection, never an authorization lookup.
    let sid = lookup_account_sid(name)?;
    let principal = principal_for_sid(&sid)?;
    if principal.name() != name {
        return Err(permission_denied(
            "worker account name does not match its native SID",
        ));
    }
    Ok(principal)
}

pub(super) fn verify_worker_principal(principal: &WorkerPrincipal) -> io::Result<()> {
    if principal.principal_kind() != PrincipalKind::WindowsSid {
        return Err(invalid_data("worker principal kind does not match Windows"));
    }
    let sid = principal_sid(principal)?;
    let current = principal_for_sid(&sid)?;
    if &current != principal {
        return Err(permission_denied("worker SID/name identity drift detected"));
    }
    Ok(())
}

fn principal_for_sid(sid: &[u8]) -> io::Result<WorkerPrincipal> {
    let id = sid_to_string(sid.as_ptr().cast())?;
    let name = account_name_for_sid(sid)?;
    WorkerPrincipal::new(PrincipalKind::WindowsSid, id, name)
}

fn principal_sid(principal: &WorkerPrincipal) -> io::Result<Vec<u8>> {
    if principal.principal_kind() != PrincipalKind::WindowsSid {
        return Err(invalid_data("worker principal kind does not match Windows"));
    }
    let input = wide(principal.principal_id());
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(input.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = LocalAllocation(sid);
    let length = unsafe { GetLengthSid(sid.0) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut result = vec![0_u8; length as usize];
    if unsafe { CopySid(length, result.as_mut_ptr().cast(), sid.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

fn account_name_for_sid(sid: &[u8]) -> io::Result<String> {
    let mut name_size = 0;
    let mut domain_size = 0;
    let mut sid_use = 0;
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_ptr().cast(),
            std::ptr::null_mut(),
            &mut name_size,
            std::ptr::null_mut(),
            &mut domain_size,
            &mut sid_use,
        );
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(io::Error::last_os_error());
    }
    let mut name = vec![0_u16; name_size as usize];
    let mut domain = vec![0_u16; domain_size as usize];
    if unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_ptr().cast(),
            name.as_mut_ptr(),
            &mut name_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut sid_use,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    validate_worker_sid_name_use(sid_use)?;
    let length = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    String::from_utf16(&name[..length])
        .map_err(|_| invalid_data("Windows returned a non-UTF-16 account name"))
}

fn validate_worker_sid_name_use(sid_name_use: i32) -> io::Result<()> {
    if sid_name_use != SID_TYPE_USER {
        return Err(permission_denied(
            "worker SID must resolve to an individual user account",
        ));
    }
    Ok(())
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn GetFileAttributesW(file_name: *const u16) -> u32;
    fn CreateDirectoryW(
        path_name: *const u16,
        security_attributes: *const SecurityAttributes,
    ) -> i32;
    fn CreateFileW(
        file_name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const SecurityAttributes,
        creation_disposition: u32,
        flags_and_attributes: u32,
        template_file: *mut c_void,
    ) -> *mut c_void;
    fn GetFileInformationByHandle(
        file: *mut c_void,
        information: *mut ByHandleFileInformation,
    ) -> i32;
    fn GetFileInformationByHandleEx(
        file: *mut c_void,
        information_class: u32,
        information: *mut c_void,
        information_size: u32,
    ) -> i32;
    #[allow(dead_code)]
    fn SetFileInformationByHandle(
        file: *mut c_void,
        information_class: u32,
        information: *const c_void,
        information_size: u32,
    ) -> i32;
    fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn GetLastError() -> u32;
    fn SetLastError(error: u32);
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(process: *mut c_void, exit_code: *mut u32) -> i32;
    fn GetFullPathNameW(
        file_name: *const u16,
        buffer_length: u32,
        buffer: *mut u16,
        file_part: *mut *mut u16,
    ) -> u32;
    fn GetFinalPathNameByHandleW(
        file: *mut c_void,
        path: *mut u16,
        path_length: u32,
        flags: u32,
    ) -> u32;
    #[cfg(test)]
    fn GetShortPathNameW(long_path: *const u16, short_path: *mut u16, buffer_length: u32) -> u32;
    fn CreateMutexW(
        mutex_attributes: *const SecurityAttributes,
        initial_owner: i32,
        name: *const u16,
    ) -> *mut c_void;
    fn ReleaseMutex(mutex: *mut c_void) -> i32;
    fn CompareStringOrdinal(
        first: *const u16,
        first_length: i32,
        second: *const u16,
        second_length: i32,
        ignore_case: i32,
    ) -> i32;
    fn CharUpperBuffW(buffer: *mut u16, length: u32) -> u32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut *mut c_void,
        desired_access: u32,
        object_attributes: *mut ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        extended_attributes: *const c_void,
        extended_attributes_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

pub(super) fn create_private_manifest_staging_directory(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    if is_test_owner(owner) {
        return std::fs::create_dir(path);
    }

    let (principal, kind) = match owner {
        ManifestOwner::System => ("unused".to_owned(), AclKind::Staging),
        ManifestOwner::User => (principal.principal_id().to_owned(), AclKind::UserDirectory),
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    };
    let wide_sddl = wide(&acl_sddl(&principal, kind));
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
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor.0,
        inherit_handle: 0,
    };
    let path = wide_os(path);
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn replace_file(temporary: &Path, destination: &Path) -> io::Result<()> {
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

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

pub(super) fn publish_manifest_directory(staging: &Path, destination: &Path) -> io::Result<()> {
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    require_kind(staging, true)?;
    let staging = wide_os(staging);
    let destination_path = destination;
    let destination = wide_os(destination);
    if unsafe {
        MoveFileExW(
            staging.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } != 0
    {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if std::fs::symlink_metadata(destination_path).is_ok() {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "manifest destination already exists",
        ))
    } else {
        Err(error)
    }
}

pub(super) fn harden_manifest_directory(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_kind(path, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    match owner {
        ManifestOwner::System => {
            apply_acl(path, worker, AclKind::Directory)?;
            inspect_acl(path, worker, AclKind::Directory)
        }
        ManifestOwner::User => {
            apply_user_acl(path, worker, AclKind::UserDirectory)?;
            inspect_user_acl(path, worker, AclKind::UserDirectory)
        }
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    }
}

pub(super) fn harden_manifest_file(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_kind(path, false)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    match owner {
        ManifestOwner::System => {
            apply_acl(path, worker, AclKind::Manifest)?;
            inspect_acl(path, worker, AclKind::Manifest)
        }
        ManifestOwner::User => {
            apply_user_acl(path, worker, AclKind::UserFile)?;
            inspect_user_acl(path, worker, AclKind::UserFile)
        }
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    }
}

pub(super) fn open_manifest_lock(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<std::fs::File> {
    let created = create_private_file_with_sharing(
        path,
        owner,
        principal,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    );
    let file = match created {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            verify_private_file_security(path, owner, principal)?;
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)?
        }
        Err(error) => return Err(error),
    };
    verify_private_file_security(path, owner, principal)?;
    Ok(file)
}

pub(super) fn verify_private_file_security(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    require_kind(path, false)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    match owner {
        ManifestOwner::System => inspect_private_acl(path, AclKind::Lock),
        ManifestOwner::User => inspect_user_acl(path, principal, AclKind::UserFile),
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    }
}

pub(super) fn create_private_file(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<std::fs::File> {
    create_private_file_with_sharing(
        path,
        owner,
        principal,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}

pub(super) fn private_file_identity(path: &Path) -> io::Result<PrivateFileIdentity> {
    let (_file, information) = open_private_file_handle(path)?;
    Ok(file_identity(&information))
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn private_file_identity_from_handle(
    file: &std::fs::File,
) -> io::Result<PrivateFileIdentity> {
    use std::os::windows::io::AsRawHandle;

    let mut information = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.file_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(permission_denied(
            "private publication handle is not a regular non-reparse file",
        ));
    }
    Ok(file_identity(&information))
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn verify_private_file_handle_security(
    file: &std::fs::File,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
) -> io::Result<()> {
    private_file_identity_from_handle(file)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    match owner {
        ManifestOwner::System => inspect_handle_private_acl(file, AclKind::Lock),
        ManifestOwner::User => inspect_handle_user_acl(file, principal, AclKind::UserFile),
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    }
}

#[allow(dead_code)] // Consumed through the deferred T0.13 publication adapter.
pub(super) fn publish_private_file_no_replace(
    file: &std::fs::File,
    temporary: &Path,
    destination: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<()> {
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    if private_file_identity_from_handle(file)? != expected_identity {
        return Err(permission_denied(
            "private publication handle identity changed",
        ));
    }
    drop(open_verified_private_file_for_read(
        temporary,
        owner,
        principal,
        expected_identity,
    )?);
    let temporary_wide = wide_os(temporary);
    let destination_wide = wide_os(destination);
    if unsafe {
        MoveFileExW(
            temporary_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if std::fs::symlink_metadata(destination).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "private publication destination already exists",
            ));
        }
        return Err(error);
    }
    #[cfg(test)]
    record_private_publication_phase(PrivatePublicationPhase::WriteThroughMove);
    drop(open_verified_private_file_for_read(
        destination,
        owner,
        principal,
        expected_identity,
    )?);
    #[cfg(test)]
    record_private_publication_phase(PrivatePublicationPhase::DestinationIdentityVerified);
    Ok(())
}

pub(super) fn open_verified_private_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<std::fs::File> {
    let (file, information) = open_private_file_handle(path)?;
    if file_identity(&information) != expected_identity {
        return Err(permission_denied("private store target identity changed"));
    }
    if !is_test_owner(owner) {
        match owner {
            ManifestOwner::System => inspect_handle_private_acl(&file, AclKind::Lock)?,
            ManifestOwner::User => inspect_handle_user_acl(&file, principal, AclKind::UserFile)?,
            #[cfg(test)]
            ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
        }
    }
    Ok(file)
}

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(crate) struct PrivateFileRemoval {
    file: std::fs::File,
}

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(super) fn prepare_verified_private_file_removal(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    expected_identity: PrivateFileIdentity,
) -> io::Result<PrivateFileRemoval> {
    let (file, information) =
        open_private_file_handle_with_access(path, GENERIC_READ | DELETE_ACCESS)?;
    if file_identity(&information) != expected_identity {
        return Err(permission_denied("private store target identity changed"));
    }
    if !is_test_owner(owner) {
        match owner {
            ManifestOwner::System => inspect_handle_private_acl(&file, AclKind::Lock)?,
            ManifestOwner::User => inspect_handle_user_acl(&file, principal, AclKind::UserFile)?,
            #[cfg(test)]
            ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
        }
    }
    Ok(PrivateFileRemoval { file })
}

#[allow(dead_code)] // Source-including manifest tests omit authorization execution.
pub(super) fn consume_verified_private_file(removal: PrivateFileRemoval) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    const FILE_DISPOSITION_INFO: u32 = 4;
    let information = FileDispositionInformation { delete_file: 1 };
    if unsafe {
        SetFileInformationByHandle(
            removal.file.as_raw_handle(),
            FILE_DISPOSITION_INFO,
            std::ptr::addr_of!(information).cast(),
            std::mem::size_of::<FileDispositionInformation>() as u32,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_private_file_handle(path: &Path) -> io::Result<(std::fs::File, ByHandleFileInformation)> {
    open_private_file_handle_with_access(path, GENERIC_READ)
}

fn open_authorization_executable_handle(
    path: &Path,
) -> io::Result<(std::fs::File, ByHandleFileInformation)> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    let path = wide_os(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_handle(handle) };
    let mut information = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.file_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(permission_denied(
            "setup authorization target is not a regular local file",
        ));
    }
    Ok((file, information))
}

fn open_private_file_handle_with_access(
    path: &Path,
    desired_access: u32,
) -> io::Result<(std::fs::File, ByHandleFileInformation)> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    let path = wide_os(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_handle(handle) };
    let mut information = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.file_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(permission_denied(
            "private store target is not a regular file",
        ));
    }
    Ok((file, information))
}

fn file_identity(information: &ByHandleFileInformation) -> PrivateFileIdentity {
    PrivateFileIdentity::new(
        u64::from(information.volume_serial_number),
        (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low),
    )
}

fn create_private_file_with_sharing(
    path: &Path,
    owner: ManifestOwner,
    principal: &WorkerPrincipal,
    share_mode: u32,
) -> io::Result<std::fs::File> {
    if is_test_owner(owner) {
        use std::os::windows::fs::OpenOptionsExt;
        return std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(share_mode)
            .open(path);
    }

    let (principal, kind) = match owner {
        ManifestOwner::System => ("unused".to_owned(), AclKind::Lock),
        ManifestOwner::User => (principal.principal_id().to_owned(), AclKind::UserFile),
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    };
    let wide_sddl = wide(&acl_sddl(&principal, kind));
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
    let attributes = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        security_descriptor: descriptor.0,
        inherit_handle: 0,
    };
    let path = wide_os(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share_mode,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    use std::os::windows::io::FromRawHandle;
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}

pub(super) fn verify_manifest_security(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<()> {
    require_kind(path, false)?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_kind(parent, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    match owner {
        ManifestOwner::System => {
            inspect_acl(parent, worker, AclKind::Directory)?;
            inspect_acl(path, worker, AclKind::Manifest)
        }
        ManifestOwner::User => {
            inspect_user_acl(parent, worker, AclKind::UserDirectory)?;
            inspect_user_acl(path, worker, AclKind::UserFile)
        }
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    }
}

pub(super) fn open_verified_manifest_file_for_read(
    path: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<std::fs::File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("manifest path has no parent directory"))?;
    require_kind(parent, true)?;
    verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
    if !is_test_owner(owner) {
        match owner {
            ManifestOwner::System => inspect_acl(parent, worker, AclKind::Directory)?,
            ManifestOwner::User => inspect_user_acl(parent, worker, AclKind::UserDirectory)?,
            #[cfg(test)]
            ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
        }
    }
    let path = wide_os(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_handle(handle) };
    let mut information = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if information.file_attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(permission_denied("manifest target is not a regular file"));
    }
    if !is_test_owner(owner) {
        match owner {
            ManifestOwner::System => inspect_handle_acl(&file, worker, AclKind::Manifest)?,
            ManifestOwner::User => inspect_handle_user_acl(&file, worker, AclKind::UserFile)?,
            #[cfg(test)]
            ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
        }
        verify_manifest_ancestors(parent, owner, worker, trusted_root)?;
        match owner {
            ManifestOwner::System => inspect_acl(parent, worker, AclKind::Directory)?,
            ManifestOwner::User => inspect_user_acl(parent, worker, AclKind::UserDirectory)?,
            #[cfg(test)]
            ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
        }
    }
    Ok(file)
}

pub(super) fn verify_manifest_file_target(path: &Path) -> io::Result<()> {
    require_kind(path, false)
}

pub(super) fn verify_manifest_directory_security(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_kind(directory, true)?;
    if is_test_owner(owner) {
        return Ok(());
    }
    match owner {
        ManifestOwner::System => inspect_acl(directory, worker, AclKind::Directory),
        ManifestOwner::User => inspect_user_acl(directory, worker, AclKind::UserDirectory),
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
    }
}

pub(super) fn verify_manifest_parent_chain(
    parent: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    if matches!(owner, ManifestOwner::User) {
        return verify_user_manifest_ancestors(parent, parent, worker);
    }
    let mut current = Some(parent);
    while let Some(ancestor) = current {
        require_kind(ancestor, true)?;
        if !is_test_owner(owner) {
            match owner {
                ManifestOwner::System => inspect_ancestor_acl(ancestor, worker)?,
                ManifestOwner::User => unreachable!(),
                #[cfg(test)]
                ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => {
                    unreachable!()
                }
            }
        }
        current = ancestor.parent();
    }
    Ok(())
}

pub(super) fn verify_manifest_ancestors(
    directory: &Path,
    owner: ManifestOwner,
    worker: &WorkerPrincipal,
    trusted_root: &Path,
) -> io::Result<()> {
    let system_owner = matches!(owner, ManifestOwner::System);
    if (system_owner && directory != trusted_root)
        || (!system_owner && !directory.starts_with(trusted_root))
    {
        return Err(permission_denied(
            "manifest directory is outside its trusted root",
        ));
    }
    if is_test_owner(owner) {
        return require_kind(directory, true);
    }
    if matches!(owner, ManifestOwner::User) {
        return verify_user_manifest_ancestors(directory, trusted_root, worker);
    }
    require_kind(directory, true)?;
    let mut current = directory.parent();
    while let Some(ancestor) = current {
        require_kind(ancestor, true)?;
        match owner {
            ManifestOwner::System => inspect_ancestor_acl(ancestor, worker)?,
            ManifestOwner::User => unreachable!(),
            #[cfg(test)]
            ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => unreachable!(),
        }
        if matches!(owner, ManifestOwner::User) && ancestor == trusted_root {
            return Ok(());
        }
        current = ancestor.parent();
    }
    if system_owner {
        Ok(())
    } else {
        Err(permission_denied(
            "manifest trusted root is not an ancestor",
        ))
    }
}

fn verify_user_manifest_ancestors(
    directory: &Path,
    trusted_root: &Path,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    require_kind(directory, true)?;
    if directory != trusted_root {
        let mut current = directory.parent();
        while let Some(ancestor) = current {
            if ancestor == trusted_root {
                break;
            }
            require_kind(ancestor, true)?;
            if inspect_user_ancestor_acl(ancestor, worker)? != UserAncestorOwner::User {
                return Err(permission_denied(
                    "user state directory is not owned by the current user",
                ));
            }
            current = ancestor.parent();
        }
        if current.is_none() {
            return Err(permission_denied(
                "manifest trusted root is not an ancestor",
            ));
        }
    }

    require_kind(trusted_root, true)?;
    if inspect_user_ancestor_acl(trusted_root, worker)? != UserAncestorOwner::User {
        return Err(permission_denied(
            "user state root is not owned by the current user",
        ));
    }

    let mut reached_system_owner = false;
    let mut current = trusted_root.parent();
    while let Some(ancestor) = current {
        require_kind(ancestor, true)?;
        validate_user_ancestor_owner_transition(
            inspect_user_ancestor_acl(ancestor, worker)?,
            &mut reached_system_owner,
        )?;
        current = ancestor.parent();
    }
    Ok(())
}

fn validate_user_ancestor_owner_transition(
    owner: UserAncestorOwner,
    reached_system_owner: &mut bool,
) -> io::Result<()> {
    match owner {
        UserAncestorOwner::User if !*reached_system_owner => Ok(()),
        UserAncestorOwner::TrustedSystem => {
            *reached_system_owner = true;
            Ok(())
        }
        UserAncestorOwner::User | UserAncestorOwner::Unexpected => Err(permission_denied(
            "user state ancestor has an unrelated or invalid owner transition",
        )),
    }
}

fn is_test_owner(owner: ManifestOwner) -> bool {
    match owner {
        ManifestOwner::System | ManifestOwner::User => false,
        #[cfg(test)]
        ManifestOwner::CurrentProcess | ManifestOwner::CurrentProcessWorker => true,
    }
}

fn apply_acl(path: &Path, worker: &WorkerPrincipal, kind: AclKind) -> io::Result<()> {
    let sddl = acl_sddl(worker.principal_id(), kind);
    apply_sddl(path, &sddl)
}

fn apply_user_acl(path: &Path, worker: &WorkerPrincipal, kind: AclKind) -> io::Result<()> {
    apply_sddl(path, &acl_sddl(worker.principal_id(), kind))
}

fn apply_sddl(path: &Path, sddl: &str) -> io::Result<()> {
    let wide_sddl = wide(sddl);
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
        AclKind::Lock | AclKind::Staging => "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned(),
        AclKind::UserFile => {
            format!("O:{worker_sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{worker_sid})")
        }
        AclKind::UserDirectory => {
            format!("O:{worker_sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{worker_sid})")
        }
    }
}

fn inspect_acl(path: &Path, worker: &WorkerPrincipal, kind: AclKind) -> io::Result<()> {
    let worker = principal_sid(worker)?;
    inspect_acl_with_worker(path, &worker, kind)
}

fn inspect_user_acl(path: &Path, worker: &WorkerPrincipal, kind: AclKind) -> io::Result<()> {
    let user = principal_sid(worker)?;
    inspect_acl_with_worker(path, &user, kind)
}

fn inspect_private_acl(path: &Path, kind: AclKind) -> io::Result<()> {
    // Private lock/temporary/intent ACLs contain only SYSTEM and
    // Administrators, so verification must not depend on any worker identity.
    let non_worker = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    inspect_acl_with_worker(path, &non_worker, kind)
}

fn inspect_acl_with_worker(path: &Path, worker: &[u8], kind: AclKind) -> io::Result<()> {
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
    inspect_security_descriptor(owner, dacl, descriptor.0, worker, kind)
}

fn inspect_handle_acl(
    file: &std::fs::File,
    worker: &WorkerPrincipal,
    kind: AclKind,
) -> io::Result<()> {
    let worker = principal_sid(worker)?;
    inspect_handle_acl_with_principal(file, &worker, kind)
}

fn inspect_handle_user_acl(
    file: &std::fs::File,
    worker: &WorkerPrincipal,
    kind: AclKind,
) -> io::Result<()> {
    let user = principal_sid(worker)?;
    inspect_handle_acl_with_principal(file, &user, kind)
}

fn inspect_handle_private_acl(file: &std::fs::File, kind: AclKind) -> io::Result<()> {
    let non_worker = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    inspect_handle_acl_with_principal(file, &non_worker, kind)
}

fn inspect_authorization_executable_acl(
    file: &std::fs::File,
    worker: &WorkerPrincipal,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
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
    let _descriptor = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(permission_denied(
            "setup authorization executable security descriptor is incomplete",
        ));
    }
    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let trusted_installer = lookup_account_sid("NT SERVICE\\TrustedInstaller")?;
    let worker = principal_sid(worker)?;
    let trusted_owner = unsafe { EqualSid(owner, administrators.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, system.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, trusted_installer.as_ptr().cast()) } != 0;
    let entries = inspect_aces(dacl, &system, &administrators, &trusted_installer, &worker)?;
    validate_authorization_executable_acl(trusted_owner, &entries)
}

fn inspect_authorization_ancestor_acl(path: &Path, worker: &WorkerPrincipal) -> io::Result<()> {
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
    let _descriptor = LocalAllocation(descriptor);
    if owner.is_null() || dacl.is_null() {
        return Err(permission_denied(
            "setup authorization ancestor security descriptor is incomplete",
        ));
    }
    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let trusted_installer = lookup_account_sid("NT SERVICE\\TrustedInstaller")?;
    let worker = principal_sid(worker)?;
    let trusted_owner = unsafe { EqualSid(owner, administrators.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, system.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, trusted_installer.as_ptr().cast()) } != 0;
    let entries = inspect_aces(dacl, &system, &administrators, &trusted_installer, &worker)?;
    validate_authorization_ancestor_acl(trusted_owner, &entries)
}

fn validate_authorization_executable_acl(
    trusted_owner: bool,
    entries: &[AceInspection],
) -> io::Result<()> {
    if !trusted_owner {
        return Err(permission_denied(
            "setup authorization executable is not owned by a trusted system principal",
        ));
    }
    if entries.iter().any(|entry| {
        entry.allowed
            && entry.flags & INHERIT_ONLY_ACE == 0
            && !matches!(
                entry.principal,
                Principal::System | Principal::Administrators | Principal::TrustedInstaller
            )
            && entry.mask & FILE_MUTATION_ACCESS != 0
    }) {
        return Err(permission_denied(
            "setup authorization executable is writable by an untrusted principal",
        ));
    }
    Ok(())
}

fn validate_authorization_ancestor_acl(
    trusted_owner: bool,
    entries: &[AceInspection],
) -> io::Result<()> {
    if !trusted_owner {
        return Err(permission_denied(
            "setup authorization executable has an untrusted ancestor owner",
        ));
    }
    if entries.iter().any(|entry| {
        entry.allowed
            && entry.flags & INHERIT_ONLY_ACE == 0
            && !matches!(
                entry.principal,
                Principal::System | Principal::Administrators | Principal::TrustedInstaller
            )
            && entry.mask & PARENT_TAKEOVER_ACCESS != 0
    }) {
        return Err(permission_denied(
            "setup authorization executable has a replaceable ancestor",
        ));
    }
    Ok(())
}

fn inspect_handle_acl_with_principal(
    file: &std::fs::File,
    principal: &[u8],
    kind: AclKind,
) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
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
    inspect_security_descriptor(owner, dacl, descriptor.0, principal, kind)
}

fn inspect_security_descriptor(
    owner: *mut c_void,
    dacl: *mut Acl,
    descriptor: *mut c_void,
    worker: &[u8],
    kind: AclKind,
) -> io::Result<()> {
    if dacl.is_null() || owner.is_null() {
        return Err(permission_denied(
            "manifest security descriptor is incomplete",
        ));
    }

    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let inspection = AclInspection {
        owner_matches_policy: if matches!(kind, AclKind::UserFile | AclKind::UserDirectory) {
            (unsafe { EqualSid(owner, worker.as_ptr().cast()) }) != 0
        } else {
            (unsafe { EqualSid(owner, administrators.as_ptr().cast()) }) != 0
        },
        dacl_is_protected: control & SE_DACL_PROTECTED != 0,
        entries: inspect_aces(dacl, &system, &administrators, &system, worker)?,
    };
    validate_acl_contract(&inspection, kind)
}

fn inspect_ancestor_acl(path: &Path, worker: &WorkerPrincipal) -> io::Result<()> {
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
    let _descriptor = LocalAllocation(descriptor);
    if dacl.is_null() || owner.is_null() {
        return Err(permission_denied(
            "manifest ancestor security descriptor is incomplete",
        ));
    }
    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let trusted_installer = lookup_account_sid("NT SERVICE\\TrustedInstaller")?;
    let worker = principal_sid(worker)?;
    validate_ancestor_entries(
        unsafe { EqualSid(owner, worker.as_ptr().cast()) } != 0,
        &inspect_aces(dacl, &system, &administrators, &trusted_installer, &worker)?,
    )
}

fn inspect_user_ancestor_acl(
    path: &Path,
    worker: &WorkerPrincipal,
) -> io::Result<UserAncestorOwner> {
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
    let _descriptor = LocalAllocation(descriptor);
    if dacl.is_null() || owner.is_null() {
        return Err(permission_denied(
            "user state ancestor security descriptor is incomplete",
        ));
    }
    let administrators = well_known_sid(WIN_BUILTIN_ADMINISTRATORS_SID)?;
    let system = well_known_sid(WIN_LOCAL_SYSTEM_SID)?;
    let trusted_installer = lookup_account_sid("NT SERVICE\\TrustedInstaller")?;
    let user = principal_sid(worker)?;
    let owner = if unsafe { EqualSid(owner, user.as_ptr().cast()) } != 0 {
        UserAncestorOwner::User
    } else if unsafe { EqualSid(owner, system.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, administrators.as_ptr().cast()) } != 0
        || unsafe { EqualSid(owner, trusted_installer.as_ptr().cast()) } != 0
    {
        UserAncestorOwner::TrustedSystem
    } else {
        UserAncestorOwner::Unexpected
    };
    let entries = inspect_aces(dacl, &system, &administrators, &trusted_installer, &user)?;
    validate_user_ancestor_entries(owner, &entries)?;
    Ok(owner)
}

fn validate_ancestor_entries(worker_is_owner: bool, entries: &[AceInspection]) -> io::Result<()> {
    if worker_is_owner {
        return Err(permission_denied(
            "configured worker owns a manifest ancestor",
        ));
    }
    for entry in entries {
        let applies_here = entry.flags & INHERIT_ONLY_ACE == 0;
        let trusted_principal = matches!(
            entry.principal,
            Principal::System | Principal::Administrators | Principal::TrustedInstaller
        );
        if entry.allowed
            && applies_here
            && !trusted_principal
            && entry.mask & PARENT_TAKEOVER_ACCESS != 0
        {
            return Err(permission_denied(
                "manifest ancestor grants delete-child or ACL takeover access",
            ));
        }
    }
    Ok(())
}

fn validate_user_ancestor_entries(
    owner: UserAncestorOwner,
    entries: &[AceInspection],
) -> io::Result<()> {
    if owner == UserAncestorOwner::Unexpected {
        return Err(permission_denied(
            "user state ancestor has an unrelated owner",
        ));
    }
    for entry in entries {
        let applies_here = entry.flags & INHERIT_ONLY_ACE == 0;
        let trusted_principal = matches!(
            entry.principal,
            Principal::System
                | Principal::Administrators
                | Principal::TrustedInstaller
                | Principal::Worker
        );
        if entry.allowed
            && applies_here
            && !trusted_principal
            && entry.mask & PARENT_TAKEOVER_ACCESS != 0
        {
            return Err(permission_denied(
                "user state ancestor grants another principal takeover access",
            ));
        }
    }
    Ok(())
}

fn validate_acl_contract(inspection: &AclInspection, kind: AclKind) -> io::Result<()> {
    if !inspection.owner_matches_policy {
        return Err(permission_denied(
            "store ACL owner does not match the selected scope",
        ));
    }
    if !inspection.dacl_is_protected {
        return Err(permission_denied(
            "manifest DACL must be protected from inherited grants",
        ));
    }
    let inherited_flags = if matches!(kind, AclKind::Directory | AclKind::UserDirectory) {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    let mut expected = vec![
        AceInspection {
            principal: Principal::System,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        },
        AceInspection {
            principal: Principal::Administrators,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        },
    ];
    match kind {
        AclKind::Manifest => expected.push(AceInspection {
            principal: Principal::Worker,
            mask: FILE_READ,
            flags: 0,
            allowed: true,
        }),
        AclKind::Directory => expected.push(AceInspection {
            principal: Principal::Worker,
            mask: FILE_READ | FILE_EXECUTE,
            flags: inherited_flags,
            allowed: true,
        }),
        AclKind::UserFile | AclKind::UserDirectory => expected.push(AceInspection {
            principal: Principal::Worker,
            mask: FILE_ALL_ACCESS,
            flags: inherited_flags,
            allowed: true,
        }),
        AclKind::Lock | AclKind::Staging => {}
    }
    if inspection.entries.len() != expected.len()
        || expected
            .iter()
            .any(|entry| !inspection.entries.contains(entry))
    {
        return Err(permission_denied(
            "manifest DACL does not match the exact principal and rights contract",
        ));
    }
    Ok(())
}

fn inspect_aces(
    acl: *const Acl,
    system: &[u8],
    administrators: &[u8],
    trusted_installer: &[u8],
    worker: &[u8],
) -> io::Result<Vec<AceInspection>> {
    let mut entries = Vec::with_capacity(unsafe { (*acl).ace_count as usize });
    for index in 0..unsafe { (*acl).ace_count as u32 } {
        let mut raw = std::ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*raw.cast::<AceHeader>() };
        if !matches!(
            header.kind,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
        ) {
            entries.push(AceInspection {
                principal: Principal::Unexpected,
                mask: PARENT_TAKEOVER_ACCESS,
                flags: header.flags,
                allowed: true,
            });
            continue;
        }
        let ace = unsafe { &*raw.cast::<AccessAllowedAce>() };
        let sid = std::ptr::addr_of!(ace.sid_start).cast::<c_void>();
        let principal = if unsafe { EqualSid(sid, system.as_ptr().cast()) } != 0 {
            Principal::System
        } else if unsafe { EqualSid(sid, administrators.as_ptr().cast()) } != 0 {
            Principal::Administrators
        } else if unsafe { EqualSid(sid, trusted_installer.as_ptr().cast()) } != 0 {
            Principal::TrustedInstaller
        } else if unsafe { EqualSid(sid, worker.as_ptr().cast()) } != 0 {
            Principal::Worker
        } else {
            Principal::Unexpected
        };
        entries.push(AceInspection {
            principal,
            mask: ace.mask,
            flags: ace.header.flags,
            allowed: ace.header.kind == ACCESS_ALLOWED_ACE_TYPE,
        });
    }
    Ok(entries)
}

fn current_user_sid() -> io::Result<Vec<u8>> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let mut required = 0;
    unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_USER_CLASS,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(io::Error::last_os_error());
    }
    let mut information = vec![0_u8; required as usize];
    if unsafe {
        GetTokenInformation(
            token.0,
            TOKEN_USER_CLASS,
            information.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let token_user = unsafe { std::ptr::read_unaligned(information.as_ptr().cast::<TokenUser>()) };
    let sid_length = unsafe { GetLengthSid(token_user.user.sid) };
    if sid_length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0_u8; sid_length as usize];
    if unsafe {
        CopySid(
            sid_length,
            sid.as_mut_ptr().cast(),
            token_user.user.sid.cast_const(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
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
    let wide_path = wide_os(path);
    let attributes = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(io::Error::last_os_error());
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(permission_denied(
            "manifest security path crosses a reparse point",
        ));
    }
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

struct OwnedHandle(*mut c_void);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_principal() -> WorkerPrincipal {
        resolve_current_worker_principal().unwrap()
    }

    #[test]
    fn worker_creation_dacl_policy_rejects_extra_principals_and_access_masks() {
        let inherited = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        let valid_entries = vec![
            AceInspection {
                principal: Principal::System,
                mask: FILE_ALL_ACCESS,
                flags: inherited,
                allowed: true,
            },
            AceInspection {
                principal: Principal::Administrators,
                mask: FILE_ALL_ACCESS,
                flags: inherited,
                allowed: true,
            },
            AceInspection {
                principal: Principal::Worker,
                mask: FILE_ALL_ACCESS,
                flags: inherited,
                allowed: true,
            },
        ];
        assert!(validate_worker_creation_acl(
            &AclInspection {
                owner_matches_policy: true,
                dacl_is_protected: true,
                entries: valid_entries.clone(),
            },
            false,
        )
        .is_ok());

        let mut everyone_write = valid_entries.clone();
        everyone_write.push(AceInspection {
            principal: Principal::Unexpected,
            mask: FILE_ALL_ACCESS,
            flags: inherited,
            allowed: true,
        });
        assert!(validate_worker_creation_acl(
            &AclInspection {
                owner_matches_policy: true,
                dacl_is_protected: true,
                entries: everyone_write,
            },
            false,
        )
        .is_err());

        let mut wrong_worker_mask = valid_entries;
        wrong_worker_mask[2].mask = FILE_READ;
        assert!(validate_worker_creation_acl(
            &AclInspection {
                owner_matches_policy: true,
                dacl_is_protected: true,
                entries: wrong_worker_mask,
            },
            false,
        )
        .is_err());
    }

    #[test]
    fn system_override_ancestor_policy_rejects_untrusted_write_authority() {
        let trusted_write = AceInspection {
            principal: Principal::Worker,
            mask: FILE_ALL_ACCESS,
            flags: 0,
            allowed: true,
        };
        assert!(validate_worker_ancestor_acl(true, &[trusted_write], false).is_ok());
        let stock_system_drive_create_only = AceInspection {
            principal: Principal::Unexpected,
            mask: 0x0000_0004 | SYNCHRONIZE,
            flags: 0,
            allowed: true,
        };
        assert!(
            validate_worker_ancestor_acl(true, &[stock_system_drive_create_only], true,).is_ok()
        );
        assert!(
            validate_worker_ancestor_acl(true, &[stock_system_drive_create_only], false,).is_err()
        );
        let everyone_write = AceInspection {
            principal: Principal::Unexpected,
            mask: GENERIC_WRITE,
            flags: 0,
            allowed: true,
        };
        assert!(validate_worker_ancestor_acl(true, &[everyone_write], true).is_err());
        for takeover in [
            0x0000_0002,
            0x0000_0040,
            0x0001_0000,
            0x0004_0000,
            0x0008_0000,
            GENERIC_WRITE,
            0x1000_0000,
        ] {
            assert!(validate_worker_ancestor_acl(
                true,
                &[AceInspection {
                    principal: Principal::Unexpected,
                    mask: takeover,
                    flags: 0,
                    allowed: true,
                }],
                true,
            )
            .is_err());
        }
        assert!(validate_worker_ancestor_acl(false, &[], true).is_err());
    }

    #[test]
    fn native_windows_system_drive_acl_allows_only_the_narrow_create_policy() {
        let principal = test_principal();
        let security = WorkerCreationSecurity::new(&principal).unwrap();
        let root = WindowsWorkerPath::parse(Path::new(r"C:\Styrn")).unwrap();
        let volume = open_worker_volume_root(&root.volume_root, true).unwrap();

        verify_trusted_worker_ancestor(&volume, &security.owner_sid, true).unwrap();
    }

    #[test]
    fn existing_canonical_worker_dacl_is_rejected_without_rewrite() {
        let principal = test_principal();
        let parent = std::env::temp_dir().join(format!(
            "styrn-worker-existing-dacl-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();
        create_worker_directory_layout(&layout).unwrap();
        apply_sddl(
            &root,
            &format!(
                "O:{0}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})(A;OICI;FA;;;WD)",
                principal.principal_id()
            ),
        )
        .unwrap();
        let sentinel = root.join("sentinel.txt");
        std::fs::write(&sentinel, b"preserve\n").unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(inspect_user_acl(&root, &principal, AclKind::UserDirectory).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve\n");
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    #[ignore = "environmental: destructive only on a disposable elevated Windows host with C:\\Styrn absent"]
    fn native_windows_precreated_insecure_system_root_is_rejected_without_takeover() {
        let principal = test_principal();
        let root = Path::new(r"C:\Styrn");
        assert!(
            !root.exists(),
            "the disposable host must start without C:\\Styrn"
        );
        std::fs::create_dir(root).unwrap();
        apply_sddl(
            root,
            &format!(
                "O:{0}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})(A;OICI;FA;;;WD)",
                principal.principal_id()
            ),
        )
        .unwrap();
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            None,
        )
        .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    #[ignore = "environmental: requires native Windows volume with 8.3 alias generation enabled"]
    fn native_windows_long_and_short_prefixes_share_one_layout_lock_key() {
        let principal = test_principal();
        let security = WorkerCreationSecurity::new(&principal).unwrap();
        let parent = std::env::temp_dir().join(format!(
            "styrn worker alias parent {} {}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&parent).unwrap();
        let long = wide_os(&parent);
        let mut short = vec![0_u16; 32_768];
        let length = unsafe {
            GetShortPathNameW(
                long.as_ptr(),
                short.as_mut_ptr(),
                short.len().try_into().unwrap(),
            )
        };
        assert!(length > 0 && usize::try_from(length).unwrap() < short.len());
        short.truncate(length as usize);
        let short_parent = PathBuf::from(std::ffi::OsString::from_wide(&short));
        assert_ne!(short_parent, parent, "8.3 alias generation is unavailable");
        let long_root = WindowsWorkerPath::parse(&parent.join("Missing Worker Root")).unwrap();
        let short_root =
            WindowsWorkerPath::parse(&short_parent.join("Missing Worker Root")).unwrap();
        let long_prepared =
            prepare_worker_root(&long_root, long_root.components.len() - 1, false, &security)
                .unwrap();
        let short_prepared = prepare_worker_root(
            &short_root,
            short_root.components.len() - 1,
            false,
            &security,
        )
        .unwrap();

        assert_eq!(
            worker_layout_lock_key(
                &long_prepared.directory,
                &long_root.components[long_prepared.next_component..],
            )
            .unwrap(),
            worker_layout_lock_key(
                &short_prepared.directory,
                &short_root.components[short_prepared.next_component..],
            )
            .unwrap(),
        );
        std::fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn native_windows_absent_and_present_root_share_the_fixed_anchor_lock_key() {
        let principal = test_principal();
        let security = WorkerCreationSecurity::new(&principal).unwrap();
        let parent = std::env::temp_dir().join(format!(
            "styrn-worker-lock-transition-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&parent).unwrap();
        let path = WindowsWorkerPath::parse(&parent.join("Logical Worker Root")).unwrap();
        let anchor_components = path.components.len() - 1;
        let anchor =
            prepare_worker_lock_anchor(&path, anchor_components, false, &security).unwrap();
        let suffix = &path.components[anchor_components..];
        let absent_key = worker_layout_lock_key(&anchor, suffix).unwrap();
        std::fs::create_dir(parent.join("Logical Worker Root")).unwrap();

        let present_key = worker_layout_lock_key(&anchor, suffix).unwrap();

        assert_eq!(absent_key, present_key);
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn current_owner_creation_does_not_request_restore_privilege() {
        let principal = test_principal();
        let owner_sid = principal_sid(&principal).unwrap();

        let guard = RestorePrivilegeGuard::enable_for_owner(&owner_sid).unwrap();

        assert!(guard.token.is_none());
    }

    #[test]
    #[ignore = "environmental: requires elevated native Windows and STYRN_TEST_DISTINCT_LOCAL_WORKER naming a disposable non-administrator local account"]
    fn native_windows_distinct_worker_owner_uses_restore_privilege_without_partial_state() {
        let worker_name = std::env::var("STYRN_TEST_DISTINCT_LOCAL_WORKER")
            .expect("STYRN_TEST_DISTINCT_LOCAL_WORKER must name a disposable local account");
        let principal = resolve_named_worker_principal(&worker_name).unwrap();
        assert_ne!(principal, test_principal());
        let parent = std::env::temp_dir().join(format!(
            "styrn-worker-dedicated-owner-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&parent).unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        let creation = create_worker_directory_layout(&layout);
        if let Err(error) = &creation {
            assert!(
                !root.exists(),
                "privilege failure left a partial worker root"
            );
            panic!("dedicated worker creation failed: {error}");
        }
        creation
            .unwrap()
            .bind_after_reverify(|_| Ok::<_, ()>(()))
            .unwrap();
        for path in std::iter::once(root.as_path()).chain(
            crate::platform::WorkerDirectoryLayout::child_names()
                .into_iter()
                .map(|name| root.join(name))
                .collect::<Vec<_>>()
                .iter()
                .map(PathBuf::as_path),
        ) {
            inspect_user_acl(path, &principal, AclKind::UserDirectory).unwrap();
        }
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    #[ignore = "environmental: requires STYRN_TEST_REFS_ROOT on a native ReFS volume"]
    fn native_windows_refs_identity_uses_the_full_file_id() {
        let refs_root = PathBuf::from(
            std::env::var_os("STYRN_TEST_REFS_ROOT")
                .expect("STYRN_TEST_REFS_ROOT must name a disposable ReFS directory"),
        );
        let parent = refs_root.join(format!(
            "styrn-worker-refs-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let first = parent.join("first");
        let second = parent.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let first = open_existing_worker_path(&WindowsWorkerPath::parse(&first).unwrap()).unwrap();
        let second =
            open_existing_worker_path(&WindowsWorkerPath::parse(&second).unwrap()).unwrap();

        assert_ne!(
            worker_directory_identity(&first).unwrap(),
            worker_directory_identity(&second).unwrap()
        );
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn worker_layout_creation_does_not_inherit_a_permissive_parent_dacl() {
        let principal = test_principal();
        let parent = std::env::temp_dir().join(format!(
            "styrn-worker-dacl-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&parent).unwrap();
        apply_sddl(
            &parent,
            &format!(
                "O:{0}D:P(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{0})",
                principal.principal_id()
            ),
        )
        .unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::User,
            &principal,
            Some(&root),
        )
        .unwrap();

        create_worker_directory_layout(&layout).unwrap();

        for path in std::iter::once(root.as_path()).chain(
            crate::platform::WorkerDirectoryLayout::child_names()
                .into_iter()
                .map(|name| root.join(name))
                .collect::<Vec<_>>()
                .iter()
                .map(PathBuf::as_path),
        ) {
            inspect_user_acl(path, &principal, AclKind::UserDirectory).unwrap();
        }
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[test]
    fn system_override_rejects_a_world_writable_parent_without_creating_the_root() {
        let principal = test_principal();
        let parent = std::env::temp_dir().join(format!(
            "styrn-worker-untrusted-parent-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&parent).unwrap();
        apply_sddl(
            &parent,
            &format!(
                "O:{0}D:P(A;OICI;GA;;;WD)(A;OICI;FA;;;{0})",
                principal.principal_id()
            ),
        )
        .unwrap();
        let root = parent.join("root");
        let layout = crate::platform::resolve_worker_directory_layout(
            crate::platform::InstallationScope::System,
            &principal,
            Some(&root),
        )
        .unwrap();

        let error = create_worker_directory_layout(&layout).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.exists());
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
        std::fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn retained_worker_root_identity_detects_path_replacement() {
        let parent = std::env::temp_dir().join(format!(
            "styrn-worker-root-swap-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        let root = parent.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let path = WindowsWorkerPath::parse(&root).unwrap();
        let retained = open_existing_worker_path(&path).unwrap();
        let identity = worker_directory_identity(&retained).unwrap();
        let displaced = parent.join("displaced");
        std::fs::rename(&root, &displaced).unwrap();
        std::fs::create_dir(&root).unwrap();

        let reopened = open_existing_worker_path(&path).unwrap();

        assert_ne!(worker_directory_identity(&reopened).unwrap(), identity);
        std::fs::remove_dir_all(parent).unwrap();
    }

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
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::Staging),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        );
        assert_eq!(
            acl_sddl("worker-is-deliberately-unused", AclKind::Lock),
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        );
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::UserFile),
            "O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)"
        );
        assert_eq!(
            acl_sddl("S-1-5-21-1-2-3-1001", AclKind::UserDirectory),
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    fn authorization_executable_acl_allows_read_execute_but_rejects_user_mutation() {
        let user_read_execute = AceInspection {
            principal: Principal::Worker,
            mask: FILE_READ | FILE_EXECUTE,
            flags: 0,
            allowed: true,
        };
        assert!(validate_authorization_executable_acl(true, &[user_read_execute]).is_ok());
        assert!(validate_authorization_executable_acl(false, &[user_read_execute]).is_err());
        for principal in [Principal::Worker, Principal::Unexpected] {
            let user_write = AceInspection {
                principal,
                mask: GENERIC_WRITE,
                flags: 0,
                allowed: true,
            };
            assert!(validate_authorization_executable_acl(true, &[user_write]).is_err());
        }
        let system_write = AceInspection {
            principal: Principal::System,
            mask: FILE_ALL_ACCESS,
            flags: 0,
            allowed: true,
        };
        assert!(validate_authorization_executable_acl(true, &[system_write]).is_ok());

        let user_delete_child = AceInspection {
            principal: Principal::Worker,
            mask: 0x0000_0040,
            flags: 0,
            allowed: true,
        };
        assert!(validate_authorization_ancestor_acl(true, &[user_read_execute]).is_ok());
        assert!(validate_authorization_ancestor_acl(false, &[]).is_err());
        assert!(validate_authorization_ancestor_acl(true, &[user_delete_child]).is_err());
    }

    #[test]
    fn worker_acl_authorization_follows_stable_sid_not_account_name() {
        let first = WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-1001",
            "build-agent",
        )
        .unwrap();
        let renamed = WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-1001",
            "renamed-agent",
        )
        .unwrap();
        let replacement = WorkerPrincipal::new(
            PrincipalKind::WindowsSid,
            "S-1-5-21-1-2-3-1002",
            "build-agent",
        )
        .unwrap();

        assert_eq!(
            acl_sddl(first.principal_id(), AclKind::Manifest),
            acl_sddl(renamed.principal_id(), AclKind::Manifest)
        );
        assert_ne!(
            acl_sddl(first.principal_id(), AclKind::Manifest),
            acl_sddl(replacement.principal_id(), AclKind::Manifest)
        );
        assert_eq!(
            acl_sddl(first.principal_id(), AclKind::Lock),
            acl_sddl(replacement.principal_id(), AclKind::Lock)
        );
    }

    #[test]
    fn worker_sid_must_resolve_to_an_individual_user_account() {
        assert!(validate_worker_sid_name_use(SID_TYPE_USER).is_ok());
        for non_user in [2, 3, 4, 5, 6, 7, 8, 9] {
            assert!(
                validate_worker_sid_name_use(non_user).is_err(),
                "SID_NAME_USE {non_user} must not authorize a worker"
            );
        }
    }

    #[test]
    fn private_staging_acl_rejects_worker_inheritance_and_unexpected_principals() {
        let base = AclInspection {
            owner_matches_policy: true,
            dacl_is_protected: true,
            entries: vec![
                AceInspection {
                    principal: Principal::System,
                    mask: FILE_ALL_ACCESS,
                    flags: 0,
                    allowed: true,
                },
                AceInspection {
                    principal: Principal::Administrators,
                    mask: FILE_ALL_ACCESS,
                    flags: 0,
                    allowed: true,
                },
            ],
        };
        assert!(validate_acl_contract(&base, AclKind::Staging).is_ok());
        for principal in [Principal::Worker, Principal::Unexpected] {
            let mut entries = base.entries.clone();
            entries.push(AceInspection {
                principal,
                mask: FILE_ALL_ACCESS,
                flags: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                allowed: true,
            });
            assert!(validate_acl_contract(
                &AclInspection {
                    owner_matches_policy: true,
                    dacl_is_protected: true,
                    entries,
                },
                AclKind::Staging,
            )
            .is_err());
        }
    }

    #[test]
    fn inspection_rejects_inherited_or_explicit_worker_mutation_rights() {
        let inherited_write = AclInspection {
            owner_matches_policy: true,
            dacl_is_protected: false,
            entries: manifest_entries(),
        };
        assert!(validate_acl_contract(&inherited_write, AclKind::Manifest).is_err());

        let mut explicit_entries = manifest_entries();
        explicit_entries[2].mask |= 0x2;
        let explicit_write = AclInspection {
            owner_matches_policy: true,
            dacl_is_protected: true,
            entries: explicit_entries,
        };
        assert!(validate_acl_contract(&explicit_write, AclKind::Manifest).is_err());
    }

    #[test]
    fn inspection_rejects_users_authenticated_users_and_unexpected_principals() {
        for mask in [FILE_READ, FILE_READ | 0x2, FILE_ALL_ACCESS] {
            let mut entries = manifest_entries();
            entries.push(AceInspection {
                principal: Principal::Unexpected,
                mask,
                flags: 0,
                allowed: true,
            });
            assert!(validate_acl_contract(
                &AclInspection {
                    owner_matches_policy: true,
                    dacl_is_protected: true,
                    entries,
                },
                AclKind::Manifest,
            )
            .is_err());
        }
    }

    #[test]
    fn ancestor_rejects_worker_or_group_delete_child_and_acl_takeover() {
        for mask in [0x40, 0x0001_0000, 0x0004_0000, 0x0008_0000, 0x1000_0000] {
            for principal in [Principal::Worker, Principal::Unexpected] {
                assert!(validate_ancestor_entries(
                    false,
                    &[AceInspection {
                        principal,
                        mask,
                        flags: 0,
                        allowed: true,
                    }]
                )
                .is_err());
            }
        }
        assert!(validate_ancestor_entries(true, &[]).is_err());
        assert!(validate_ancestor_entries(
            false,
            &[AceInspection {
                principal: Principal::Unexpected,
                mask: 0x40,
                flags: INHERIT_ONLY_ACE,
                allowed: true,
            }]
        )
        .is_ok());
    }

    #[test]
    fn user_ancestor_owner_chain_allows_one_transition_to_trusted_os_owners() {
        let mut reached_system_owner = false;
        assert!(validate_user_ancestor_owner_transition(
            UserAncestorOwner::User,
            &mut reached_system_owner,
        )
        .is_ok());
        assert!(validate_user_ancestor_owner_transition(
            UserAncestorOwner::TrustedSystem,
            &mut reached_system_owner,
        )
        .is_ok());
        assert!(reached_system_owner);
        assert!(validate_user_ancestor_owner_transition(
            UserAncestorOwner::TrustedSystem,
            &mut reached_system_owner,
        )
        .is_ok());
        assert!(validate_user_ancestor_owner_transition(
            UserAncestorOwner::User,
            &mut reached_system_owner,
        )
        .is_err());

        let mut fresh_chain = false;
        assert!(validate_user_ancestor_owner_transition(
            UserAncestorOwner::Unexpected,
            &mut fresh_chain,
        )
        .is_err());
    }

    #[test]
    fn user_ancestor_acl_trusts_user_and_os_service_but_rejects_unrelated_takeover() {
        let trusted_entries = [
            AceInspection {
                principal: Principal::Worker,
                mask: PARENT_TAKEOVER_ACCESS,
                flags: 0,
                allowed: true,
            },
            AceInspection {
                principal: Principal::TrustedInstaller,
                mask: PARENT_TAKEOVER_ACCESS,
                flags: 0,
                allowed: true,
            },
        ];
        for owner in [UserAncestorOwner::User, UserAncestorOwner::TrustedSystem] {
            assert!(validate_user_ancestor_entries(owner, &trusted_entries).is_ok());
        }
        assert!(
            validate_user_ancestor_entries(UserAncestorOwner::Unexpected, &trusted_entries,)
                .is_err()
        );
        assert!(validate_user_ancestor_entries(
            UserAncestorOwner::TrustedSystem,
            &[AceInspection {
                principal: Principal::Unexpected,
                mask: PARENT_TAKEOVER_ACCESS,
                flags: 0,
                allowed: true,
            }],
        )
        .is_err());
    }

    #[test]
    fn inspection_accepts_exact_read_only_worker_contract() {
        assert!(validate_acl_contract(
            &AclInspection {
                owner_matches_policy: true,
                dacl_is_protected: true,
                entries: manifest_entries(),
            },
            AclKind::Manifest,
        )
        .is_ok());
    }

    #[test]
    fn private_file_can_be_atomically_published_while_its_handle_remains_open() {
        let root = std::env::temp_dir().join(format!(
            "styrn-private-file-publication-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let temporary = root.join("temporary");
        let destination = root.join("destination");
        let mut file =
            create_private_file(&temporary, ManifestOwner::CurrentProcess, &test_principal())
                .unwrap();
        std::io::Write::write_all(&mut file, b"complete").unwrap();
        file.sync_all().unwrap();

        replace_file(&temporary, &destination).unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"complete");
        drop(file);
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn native_private_publication_uses_write_through_before_identity_verification() {
        use std::io::Write;

        let root = std::env::temp_dir().join(format!(
            "styrn-private-write-through-{}-{}",
            std::process::id(),
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir(&root).unwrap();
        let temporary = root.join("temporary");
        let destination = root.join("destination");
        let principal = test_principal();
        let mut file = super::super::create_private_publication_file(
            &temporary,
            ManifestOwner::CurrentProcess,
            &principal,
        )
        .unwrap();
        file.write_all(b"complete").unwrap();
        trace_private_publication_for_test(true);

        file.complete_exact(b"complete")
            .unwrap()
            .publish_no_replace(&destination)
            .unwrap();

        assert_eq!(
            take_private_publication_trace_for_test(),
            vec![
                PrivatePublicationPhase::WriteThroughMove,
                PrivatePublicationPhase::DestinationIdentityVerified,
            ]
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"complete");
        assert!(!temporary.exists());
        std::fs::remove_file(destination).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    fn manifest_entries() -> Vec<AceInspection> {
        vec![
            AceInspection {
                principal: Principal::System,
                mask: FILE_ALL_ACCESS,
                flags: 0,
                allowed: true,
            },
            AceInspection {
                principal: Principal::Administrators,
                mask: FILE_ALL_ACCESS,
                flags: 0,
                allowed: true,
            },
            AceInspection {
                principal: Principal::Worker,
                mask: FILE_READ,
                flags: 0,
                allowed: true,
            },
        ]
    }

    #[test]
    #[ignore = "environmental: elevated Windows plus STYRN_WINDOWS_TEST_WORKER and STYRN_WINDOWS_TEST_PASSWORD"]
    fn real_windows_worker_can_read_but_cannot_mutate_or_take_over_manifest_and_receipt() {
        let worker = std::env::var("STYRN_WINDOWS_TEST_WORKER")
            .expect("STYRN_WINDOWS_TEST_WORKER must select a real unprivileged account");
        let worker_principal = resolve_named_worker_principal(&worker).unwrap();
        let password = std::env::var("STYRN_WINDOWS_TEST_PASSWORD")
            .expect("STYRN_WINDOWS_TEST_PASSWORD is required for worker impersonation");
        let public = std::path::PathBuf::from(
            std::env::var_os("PUBLIC").expect("Windows PUBLIC directory is required"),
        );
        let directory = public.join(format!(
            "styrn-acl-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        harden_manifest_directory(&directory, ManifestOwner::System, &worker_principal).unwrap();
        let manifest = directory.join("machine.toml");
        std::fs::write(&manifest, "schema_version = 1\n").unwrap();
        harden_manifest_file(&manifest, ManifestOwner::System, &worker_principal).unwrap();
        verify_manifest_security(
            &manifest,
            ManifestOwner::System,
            &worker_principal,
            &directory,
        )
        .unwrap();
        let receipt = directory.join("receipt.json");
        std::fs::write(&receipt, "{\"schema_version\":1,\"entries\":[]}\n").unwrap();
        harden_manifest_file(&receipt, ManifestOwner::System, &worker_principal).unwrap();
        verify_manifest_security(
            &receipt,
            ManifestOwner::System,
            &worker_principal,
            &directory,
        )
        .unwrap();
        let receipt_lock = directory.join(".receipt.json.lock");
        drop(create_private_file(&receipt_lock, ManifestOwner::System, &worker_principal).unwrap());
        inspect_private_acl(&receipt_lock, AclKind::Lock).unwrap();

        let replacement_directory = public.join(format!(
            "styrn-acl-replacement-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&replacement_directory).unwrap();
        let worker_sid = lookup_account_sid(&worker).unwrap();
        let worker_sid = sid_to_string(worker_sid.as_ptr().cast()).unwrap();
        apply_sddl(
            &replacement_directory,
            &format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{worker_sid})"),
        )
        .unwrap();
        let replacement = replacement_directory.join("replacement.toml");
        std::fs::write(&replacement, "replacement = true\n").unwrap();
        apply_sddl(
            &replacement,
            &format!("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{worker_sid})"),
        )
        .unwrap();

        let username = wide(&worker);
        let domain = wide(".");
        let mut password = wide(&password);
        let mut token = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                LogonUserW(
                    username.as_ptr(),
                    domain.as_ptr(),
                    password.as_ptr(),
                    2,
                    0,
                    &mut token,
                )
            },
            0,
            "LogonUserW failed: {}",
            io::Error::last_os_error()
        );
        password.fill(0);
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token) }, 0);
        let impersonation = ImpersonationGuard(token);

        assert!(std::fs::read_to_string(&manifest).is_ok());
        assert_access_denied(std::fs::OpenOptions::new().write(true).open(&manifest));
        assert_access_denied(std::fs::remove_file(&manifest));
        assert_access_denied(std::fs::rename(&manifest, directory.join("renamed.toml")));
        assert_access_denied(replace_file(&replacement, &manifest));
        assert_access_denied(apply_sddl(
            &manifest,
            &format!("O:BAD:P(A;;FA;;;{worker_sid})"),
        ));

        assert!(std::fs::read_to_string(&receipt).is_ok());
        let mut held_receipt = open_verified_manifest_file_for_read(
            &receipt,
            ManifestOwner::System,
            &worker_principal,
            &directory,
        )
        .unwrap();
        assert_access_denied(std::fs::OpenOptions::new().write(true).open(&receipt));
        assert_access_denied(std::fs::remove_file(&receipt));
        assert_access_denied(std::fs::rename(
            &receipt,
            directory.join("renamed-receipt.json"),
        ));
        assert_access_denied(replace_file(&replacement, &receipt));
        assert_access_denied(apply_sddl(
            &receipt,
            &format!("O:BAD:P(A;;FA;;;{worker_sid})"),
        ));
        assert_access_denied(std::fs::File::open(&receipt_lock));
        assert_access_denied(std::fs::OpenOptions::new().write(true).open(&receipt_lock));
        assert_access_denied(std::fs::remove_file(&receipt_lock));
        assert_access_denied(std::fs::rename(
            &receipt_lock,
            directory.join("renamed-receipt-lock"),
        ));
        assert_access_denied(apply_sddl(
            &receipt_lock,
            &format!("O:BAD:P(A;;FA;;;{worker_sid})"),
        ));

        drop(impersonation);
        let controller_replacement = directory.join("controller-replacement.json");
        let mut controller_file = create_private_file(
            &controller_replacement,
            ManifestOwner::System,
            &worker_principal,
        )
        .unwrap();
        std::io::Write::write_all(&mut controller_file, b"complete replacement\n").unwrap();
        controller_file.sync_all().unwrap();
        drop(controller_file);
        harden_manifest_file(
            &controller_replacement,
            ManifestOwner::System,
            &worker_principal,
        )
        .unwrap();
        replace_file(&controller_replacement, &receipt)
            .expect("a worker-held read-only receipt handle must share atomic replacement");
        use std::io::{Read, Seek};
        held_receipt.rewind().unwrap();
        let mut held_bytes = Vec::new();
        held_receipt.read_to_end(&mut held_bytes).unwrap();
        assert_eq!(held_bytes, b"{\"schema_version\":1,\"entries\":[]}\n");
        assert_eq!(std::fs::read(&receipt).unwrap(), b"complete replacement\n");
        drop(held_receipt);
        std::fs::remove_file(manifest).unwrap();
        std::fs::remove_file(receipt).unwrap();
        std::fs::remove_file(receipt_lock).unwrap();
        std::fs::remove_dir(directory).unwrap();
        std::fs::remove_file(replacement).unwrap();
        std::fs::remove_dir(replacement_directory).unwrap();
    }

    #[test]
    #[ignore = "environmental: elevated Windows plus STYRN_WINDOWS_TEST_WORKER and STYRN_WINDOWS_TEST_PASSWORD"]
    fn real_windows_worker_cannot_access_private_staging_or_files_before_publication() {
        let worker = std::env::var("STYRN_WINDOWS_TEST_WORKER")
            .expect("STYRN_WINDOWS_TEST_WORKER must select a real unprivileged account");
        let worker_principal = resolve_named_worker_principal(&worker).unwrap();
        let password = std::env::var("STYRN_WINDOWS_TEST_PASSWORD")
            .expect("STYRN_WINDOWS_TEST_PASSWORD is required for worker impersonation");
        let public = std::path::PathBuf::from(
            std::env::var_os("PUBLIC").expect("Windows PUBLIC directory is required"),
        );
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let parent = public.join(format!("styrn-staging-parent-{nonce}"));
        std::fs::create_dir(&parent).unwrap();
        harden_manifest_directory(&parent, ManifestOwner::System, &worker_principal).unwrap();

        let staging = parent.join("staging");
        create_private_manifest_staging_directory(
            &staging,
            ManifestOwner::System,
            &worker_principal,
        )
        .unwrap();
        inspect_private_acl(&staging, AclKind::Staging).unwrap();
        assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
        let private_file = parent.join("receipt-intent.json");
        let mut private =
            create_private_file(&private_file, ManifestOwner::System, &worker_principal).unwrap();
        std::io::Write::write_all(&mut private, b"private receipt intent").unwrap();
        private.sync_all().unwrap();
        drop(private);
        inspect_private_acl(&private_file, AclKind::Lock).unwrap();

        let replacement = public.join(format!("styrn-staging-replacement-{nonce}"));
        std::fs::create_dir(&replacement).unwrap();
        let worker_sid = lookup_account_sid(&worker).unwrap();
        let worker_sid = sid_to_string(worker_sid.as_ptr().cast()).unwrap();
        apply_sddl(
            &replacement,
            &format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{worker_sid})"),
        )
        .unwrap();

        let swap_control = public.join(format!("styrn-staging-swap-control-{nonce}"));
        std::fs::create_dir(&swap_control).unwrap();
        apply_sddl(
            &swap_control,
            &format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{worker_sid})"),
        )
        .unwrap();
        let control_destination = swap_control.join("destination");
        let control_replacement = swap_control.join("replacement");
        std::fs::create_dir(&control_destination).unwrap();
        std::fs::create_dir(&control_replacement).unwrap();
        let control_marker = control_replacement.join("replacement-marker");
        std::fs::write(&control_marker, b"replacement reached").unwrap();

        let username = wide(&worker);
        let domain = wide(".");
        let mut password = wide(&password);
        let mut token = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                LogonUserW(
                    username.as_ptr(),
                    domain.as_ptr(),
                    password.as_ptr(),
                    2,
                    0,
                    &mut token,
                )
            },
            0,
            "LogonUserW failed: {}",
            io::Error::last_os_error()
        );
        password.fill(0);
        assert_ne!(unsafe { ImpersonateLoggedOnUser(token) }, 0);
        let impersonation = ImpersonationGuard(token);

        open_directory_for_read(&replacement)
            .expect("worker cannot exercise the directory-open control");
        std::fs::read_dir(&replacement).expect("worker cannot exercise the directory-list control");
        let worker_control = replacement.join("worker-control");
        std::fs::write(&worker_control, b"worker-controlled")
            .expect("worker cannot exercise the directory-create control");
        let control_swap =
            attempt_delete_then_rename_directory_swap(&control_replacement, &control_destination);
        assert!(
            matches!(
                &control_swap,
                DirectorySwapOutcome::SourceRenamedIntoDestination
            ),
            "worker-writable delete-then-rename control did not complete: {control_swap:?}"
        );

        assert_access_denied_for("open staging directory", open_directory_for_read(&staging));
        assert_access_denied_for("list staging directory", std::fs::read_dir(&staging));
        assert_access_denied_for(
            "create within staging directory",
            std::fs::write(staging.join("worker-created"), b"worker-controlled"),
        );
        assert_access_denied_for(
            "rename staging directory",
            std::fs::rename(&staging, parent.join("renamed")),
        );
        assert_access_denied_for("delete staging directory", std::fs::remove_dir(&staging));
        assert_access_denied_for("read private receipt file", std::fs::read(&private_file));
        assert_access_denied_for(
            "write private receipt file",
            std::fs::OpenOptions::new().write(true).open(&private_file),
        );
        assert_access_denied_for(
            "delete private receipt file",
            std::fs::remove_file(&private_file),
        );
        assert_access_denied_for(
            "rename private receipt file",
            std::fs::rename(&private_file, parent.join("renamed-intent.json")),
        );
        assert_access_denied_for(
            "replace private receipt file",
            replace_file(&worker_control, &private_file),
        );
        match attempt_delete_then_rename_directory_swap(&replacement, &staging) {
            DirectorySwapOutcome::Blocked { step, error } => {
                assert_eq!(step, DirectorySwapStep::DeleteDestination);
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied,
                    "delete-then-rename staging swap failed unexpectedly: {error}"
                );
            }
            DirectorySwapOutcome::SourceRenamedIntoDestination => {
                panic!("worker completed a delete-then-rename staging swap")
            }
        }

        drop(impersonation);
        assert!(
            staging.is_dir(),
            "delete-then-rename attempt removed the protected staging directory"
        );
        assert!(
            replacement.is_dir(),
            "replacement source moved despite the denied destination-delete step"
        );
        assert!(
            !control_replacement.exists(),
            "worker-writable control did not move its replacement source"
        );
        assert!(
            control_destination.join("replacement-marker").is_file(),
            "worker-writable control did not complete its replacement rename"
        );
        assert!(!staging.join("worker-created").exists());
        assert!(!parent.join("renamed").exists());
        assert!(private_file.is_file());
        assert!(!parent.join("renamed-intent.json").exists());

        std::fs::remove_dir(staging).unwrap();
        std::fs::remove_file(private_file).unwrap();
        std::fs::remove_dir(parent).unwrap();
        std::fs::remove_file(worker_control).unwrap();
        std::fs::remove_dir(replacement).unwrap();
        std::fs::remove_file(control_destination.join("replacement-marker")).unwrap();
        std::fs::remove_dir(control_destination).unwrap();
        std::fs::remove_dir(swap_control).unwrap();
    }

    fn assert_access_denied<T: std::fmt::Debug>(result: io::Result<T>) {
        assert_access_denied_for("worker mutation", result);
    }

    fn assert_access_denied_for<T: std::fmt::Debug>(operation: &str, result: io::Result<T>) {
        let error = match result {
            Ok(value) => panic!("{operation} unexpectedly succeeded: {value:?}"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            io::ErrorKind::PermissionDenied,
            "{operation}: {error}"
        );
    }

    #[derive(Debug)]
    enum DirectorySwapOutcome {
        SourceRenamedIntoDestination,
        Blocked {
            step: DirectorySwapStep,
            error: io::Error,
        },
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DirectorySwapStep {
        DeleteDestination,
        RenameSourceIntoDestination,
    }

    fn attempt_delete_then_rename_directory_swap(
        source: &Path,
        destination: &Path,
    ) -> DirectorySwapOutcome {
        if let Err(error) = std::fs::remove_dir(destination) {
            return DirectorySwapOutcome::Blocked {
                step: DirectorySwapStep::DeleteDestination,
                error,
            };
        }
        if let Err(error) = std::fs::rename(source, destination) {
            return DirectorySwapOutcome::Blocked {
                step: DirectorySwapStep::RenameSourceIntoDestination,
                error,
            };
        }
        DirectorySwapOutcome::SourceRenamedIntoDestination
    }

    fn open_directory_for_read(path: &Path) -> io::Result<()> {
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        const FILE_SHARE_DELETE: u32 = 0x4;
        const OPEN_EXISTING: u32 = 3;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        const INVALID_HANDLE_VALUE: *mut c_void = -1_isize as *mut c_void;

        let path = wide_os(path);
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        unsafe {
            CloseHandle(handle);
        }
        Ok(())
    }

    struct ImpersonationGuard(*mut c_void);

    impl Drop for ImpersonationGuard {
        fn drop(&mut self) {
            unsafe {
                RevertToSelf();
                CloseHandle(self.0);
            }
        }
    }
}
