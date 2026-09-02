pub(super) fn forge_receipt(json: &[u8]) {
    let _ = crate::setup::receipt::ReceiptDocument::from_json(json);
}
