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
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_FILE_OBJECT: u32 = 1;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const TOKEN_QUERY: u32 = 0x0008;
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
}

#[link(name = "ole32")]
unsafe extern "system" {
    fn CoInitializeEx(reserved: *mut c_void, concurrency_model: u32) -> i32;
    fn CoUninitialize();
}

pub(super) fn resolve_current_worker_principal() -> io::Result<WorkerPrincipal> {
    let sid = current_user_sid()?;
    principal_for_sid(&sid)
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
    fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(process: *mut c_void, exit_code: *mut u32) -> i32;
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
