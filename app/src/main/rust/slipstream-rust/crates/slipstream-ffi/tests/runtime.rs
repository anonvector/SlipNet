use slipstream_ffi::picoquic::picoquic_clear_crypto_errors;
use slipstream_ffi::take_crypto_errors;

#[test]
fn take_crypto_errors_returns_empty_when_clear() {
    // SAFETY: clears the per-thread crypto error queue with no inputs.
    unsafe { picoquic_clear_crypto_errors() };

    let first = take_crypto_errors();
    assert!(
        first.is_empty(),
        "expected no crypto errors, got {:?}",
        first
    );

    let second = take_crypto_errors();
    assert!(
        second.is_empty(),
        "expected no crypto errors on second call, got {:?}",
        second
    );
}
