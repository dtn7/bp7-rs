use wasm_bindgen::prelude::*;

use crate::bundle::Bundle;
use crate::dtntime::CreationTimestamp;
use crate::eid::*;
use core::convert::TryFrom;

/// Create a new standard bundle with current timestamp
#[wasm_bindgen]
pub fn new_std_bundle_now(src: &str, dst: &str, payload: &str) -> Result<JsValue, JsValue> {
    let src_eid = EndpointID::try_from(src.to_string())
        .map_err(|e| JsValue::from_str(&format!("Invalid source address: {}", e)))?;
    let dst_eid = EndpointID::try_from(dst.to_string())
        .map_err(|e| JsValue::from_str(&format!("Invalid destination address: {}", e)))?;

    let bundle =
        crate::bundle::new_std_payload_bundle(src_eid, dst_eid, payload.as_bytes().to_vec());

    serde_wasm_bindgen::to_value(&bundle)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Create a random bundle with current timestamp
#[wasm_bindgen]
pub fn rnd_bundle_now() -> Result<JsValue, JsValue> {
    let bundle = crate::helpers::rnd_bundle(CreationTimestamp::now());
    serde_wasm_bindgen::to_value(&bundle)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Encode a bundle to CBOR bytes
#[wasm_bindgen]
pub fn encode_to_cbor(bundle_js: &JsValue) -> Result<Vec<u8>, JsValue> {
    let mut bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(bundle.to_cbor())
}

/// Decode a bundle from CBOR bytes
#[wasm_bindgen]
pub fn decode_from_cbor(buf: &[u8]) -> Result<JsValue, JsValue> {
    let bundle = Bundle::try_from(buf.to_vec())
        .map_err(|e| JsValue::from_str(&format!("CBOR decode error: {}", e)))?;
    serde_wasm_bindgen::to_value(&bundle)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Get bundle ID from a bundle object
#[wasm_bindgen]
pub fn bid_from_bundle(bundle_js: &JsValue) -> Result<String, JsValue> {
    let bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(bundle.id())
}

/// Get bundle ID from CBOR bytes
#[wasm_bindgen]
pub fn bid_from_cbor(buf: &[u8]) -> Result<String, JsValue> {
    let bundle = Bundle::try_from(buf.to_vec())
        .map_err(|e| JsValue::from_str(&format!("CBOR decode error: {}", e)))?;
    Ok(bundle.id())
}

/// Get sender from a bundle object
#[wasm_bindgen]
pub fn sender_from_bundle(bundle_js: &JsValue) -> Result<String, JsValue> {
    let bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(bundle.primary.source.to_string())
}

/// Get sender from CBOR bytes
#[wasm_bindgen]
pub fn sender_from_cbor(buf: &[u8]) -> Result<String, JsValue> {
    let bundle = Bundle::try_from(buf.to_vec())
        .map_err(|e| JsValue::from_str(&format!("CBOR decode error: {}", e)))?;
    Ok(bundle.primary.source.to_string())
}

/// Get recipient from a bundle object
#[wasm_bindgen]
pub fn recipient_from_bundle(bundle_js: &JsValue) -> Result<String, JsValue> {
    let bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(bundle.primary.destination.to_string())
}

/// Get recipient from CBOR bytes
#[wasm_bindgen]
pub fn recipient_from_cbor(buf: &[u8]) -> Result<String, JsValue> {
    let bundle = Bundle::try_from(buf.to_vec())
        .map_err(|e| JsValue::from_str(&format!("CBOR decode error: {}", e)))?;
    Ok(bundle.primary.destination.to_string())
}

/// Get timestamp from a bundle object
#[wasm_bindgen]
pub fn timestamp_from_bundle(bundle_js: &JsValue) -> Result<String, JsValue> {
    let bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(bundle.primary.creation_timestamp.to_string())
}

/// Get timestamp from CBOR bytes
#[wasm_bindgen]
pub fn timestamp_from_cbor(buf: &[u8]) -> Result<String, JsValue> {
    let bundle = Bundle::try_from(buf.to_vec())
        .map_err(|e| JsValue::from_str(&format!("CBOR decode error: {}", e)))?;
    Ok(bundle.primary.creation_timestamp.to_string())
}

/// Extract payload from a bundle object
#[wasm_bindgen]
pub fn payload_from_bundle(bundle_js: &JsValue) -> Result<Option<Vec<u8>>, JsValue> {
    let bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(bundle.payload().cloned())
}

/// Extract payload from CBOR bytes
#[wasm_bindgen]
pub fn payload_from_cbor(buf: &[u8]) -> Result<Option<Vec<u8>>, JsValue> {
    let bundle = Bundle::try_from(buf.to_vec())
        .map_err(|e| JsValue::from_str(&format!("CBOR decode error: {}", e)))?;
    Ok(bundle.payload().cloned())
}

/// Validate a bundle object
#[wasm_bindgen]
pub fn valid_bundle(bundle_js: &JsValue) -> Result<bool, JsValue> {
    let bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(!bundle.primary.is_lifetime_exceeded() && bundle.validate().is_ok())
}

/// Validate CBOR bytes as a bundle
#[wasm_bindgen]
pub fn valid_cbor(buf: &[u8]) -> Result<bool, JsValue> {
    match Bundle::try_from(buf.to_vec()) {
        Ok(bundle) => Ok(!bundle.primary.is_lifetime_exceeded() && bundle.validate().is_ok()),
        Err(_) => Ok(false),
    }
}

/// Check if bundle is an administrative record
#[wasm_bindgen]
pub fn bundle_is_administrative_record(bundle_js: &JsValue) -> Result<bool, JsValue> {
    let bundle: Bundle = serde_wasm_bindgen::from_value(bundle_js.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
    Ok(bundle.is_administrative_record())
}

/// Check if CBOR bytes represent an administrative record bundle
#[wasm_bindgen]
pub fn cbor_is_administrative_record(buf: &[u8]) -> Result<bool, JsValue> {
    let bundle = Bundle::try_from(buf.to_vec())
        .map_err(|e| JsValue::from_str(&format!("CBOR decode error: {}", e)))?;
    Ok(bundle.is_administrative_record())
}
