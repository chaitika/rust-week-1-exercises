// Implement extract_tx_version function below
pub fn extract_tx_version(raw_tx_hex: &str) -> Result<u32, String> {
    // Strip an optional 0x/0X prefix; the tests supply both styles.
    let hex = raw_tx_hex
        .strip_prefix("0x")
        .or_else(|| raw_tx_hex.strip_prefix("0X"))
        .unwrap_or(raw_tx_hex);

    // A Bitcoin tx version is 4 bytes ⇒ 8 hex chars.
    if hex.len() < 8 {
        return Err("Transaction data too short".to_string());
    }

    // First 4 bytes (8 chars) contain the version, little-endian.
    let version_hex = &hex[..8];

    // Decode; any invalid digit should surface the expected message.
    let bytes = hex::decode(version_hex).map_err(|_| "Hex decode error".to_string())?;

    // Convert the 4 little-endian bytes into a host-endian u32.
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    Ok(version)
}
