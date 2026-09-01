#[path = "../../src/main.rs"]
mod styrn;

fn main() {
    let _ = styrn::platform::linux::platform_name();
}
