use crate::bundle::Bundle;
use crate::dtntime::{CreationTimestamp, DtnTimeHelpers};
use crate::eid::*;
use core::convert::TryFrom;
use stdweb::*;

js_serializable!(Bundle);
js_deserializable!(Bundle);

#[js_export]
fn new_std_bundle_now(src: String, dst: String, payload: String) -> Bundle {
    crate::bundle::new_std_payload_bundle(
        EndpointID::try_from(src).expect("invalid src address"),
        EndpointID::try_from(dst).expect("invalid dst address"),
        payload.into(),
    )
}

#[js_export]
fn rnd_bundle_now() -> Bundle {
    crate::helpers::rnd_bundle(CreationTimestamp::now())
}

#[js_export]
fn encode_to_cbor(b: Bundle) -> crate::ByteBuffer {
    b.clone().to_cbor()
}

#[js_export]
fn decode_from_cbor(buf: crate::ByteBuffer) -> Bundle {
    // TODO: correct error handling for javascript
    Bundle::try_from(buf).expect("error decoding bundle")
}
#[js_export]
fn bid_from_bundle(b: Bundle) -> String {
    b.id()
}

#[js_export]
fn bid_from_cbor(buf: crate::ByteBuffer) -> String {
    bid_from_bundle(decode_from_cbor(buf))
}
#[js_export]
fn payload_from_bundle(b: Bundle) -> Option<crate::ByteBuffer> {
    b.payload().map(|d| d.clone())
}

#[js_export]
fn payload_from_cbor(buf: crate::ByteBuffer) -> Option<crate::ByteBuffer> {
    payload_from_bundle(decode_from_cbor(buf))
}

#[js_export]
fn valid_bundle(b: Bundle) -> bool {
    !b.primary.is_lifetime_exceeded() && b.validate().is_ok()
}

#[js_export]
fn valid_cbor(buf: crate::ByteBuffer) -> bool {
    valid_bundle(decode_from_cbor(buf))
}

#[js_export]
fn sender_from_bundle(b: Bundle) -> String {
    b.primary.source.to_string()
}

#[js_export]
fn sender_from_cbor(buf: crate::ByteBuffer) -> String {
    sender_from_bundle(decode_from_cbor(buf))
}

#[js_export]
fn recipient_from_bundle(b: Bundle) -> String {
    b.primary.destination.to_string()
}

#[js_export]
fn recipient_from_cbor(buf: crate::ByteBuffer) -> String {
    recipient_from_bundle(decode_from_cbor(buf))
}

#[js_export]
fn timestamp_from_bundle(b: Bundle) -> String {
    b.primary.creation_timestamp.to_owned().to_string()
}

#[js_export]
fn timestamp_from_cbor(buf: crate::ByteBuffer) -> String {
    timestamp_from_bundle(decode_from_cbor(buf))
}

#[js_export]
fn bundle_is_administrative_record(b: Bundle) -> bool {
    b.is_administrative_record()
}

#[js_export]
fn cbor_is_administrative_record(buf: crate::ByteBuffer) -> bool {
    bundle_is_administrative_record(decode_from_cbor(buf))
}
