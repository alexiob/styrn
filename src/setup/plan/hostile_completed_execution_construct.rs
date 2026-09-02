pub(super) fn construct() {
    let _ = crate::setup::action::CompletedExecutionToken {
        pending: Vec::new(),
        ..never()
    };
}

fn never<T>() -> T {
    loop {}
}
