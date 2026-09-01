#[path = "../../src/platform/mod.rs"]
mod platform;

mod generic {
    #[cfg(target_os = "linux")]
    fn misuse() {
        let _ = crate::platform::linux::platform_name();
    }

    #[cfg(target_os = "macos")]
    fn misuse() {
        let _ = crate::platform::macos::platform_name();
    }

    #[cfg(target_os = "windows")]
    fn misuse() {
        let _ = crate::platform::windows::platform_name();
    }
}

fn main() {}
