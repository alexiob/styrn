mod setup {
    pub(crate) mod action {
        pub(crate) struct NativeMutationAuthority;
    }
}

#[path = "__PLATFORM_PATH__"]
mod platform;

fn requires_serialize<T: serde::Serialize>() {}

fn generic_consumer(
    handle: platform::DedicatedAccountHandle,
    evidence: platform::EstablishedDedicatedAccountEvidence,
) {
    println!("{handle:?}");
    requires_serialize::<platform::DedicatedAccountHandle>();
    requires_serialize::<platform::EstablishedDedicatedAccountEvidence>();
    let _ = handle.0.clone();
    let _ = evidence.selector;
    let _ = platform::DedicatedAccountFactoryAuthority(());
}

fn invoke_factory(
    handle: &platform::DedicatedAccountHandle,
    authority: &platform::DedicatedAccountFactoryAuthority,
) {
    let _ = handle.reverify_and_bind(authority, |_| ());
}

fn main() {}
