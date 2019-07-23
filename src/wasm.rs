use crate::bundle::Bundle;
use crate::dtntime::CreationTimestamp;

use stdweb::*;

js_serializable!(Bundle);
js_deserializable!(Bundle);


#[js_export]
fn rnd_bundle_now() -> Bundle {
    crate::helpers::rnd_bundle(CreationTimestamp::now())
}

#[js_export]
fn encode_to_cbor(b : Bundle) -> crate::ByteBuffer {
    b.clone().to_cbor()
}

#[js_export]
fn decode_from_cbor(buf : crate::ByteBuffer) -> Bundle {
    buf.into()
}

#[js_export]
fn payload_from_bundle(b : Bundle) -> Option<crate::ByteBuffer> {    
    b.payload().map(|d| d.clone())
}

#[js_export]
fn payload_from_cbor(buf : crate::ByteBuffer) -> Option<crate::ByteBuffer> {
    payload_from_bundle(decode_from_cbor(buf))
}

#[js_export]
fn valid_bundle(b : Bundle) -> bool {
    !b.primary.is_lifetime_exceeded() && b.validation_errors().is_none()
}

#[js_export]
fn valid_cbor(buf : crate::ByteBuffer) -> bool {
    valid_bundle(decode_from_cbor(buf))
}

#[js_export]
fn sender_from_bundle(b : Bundle) -> String {
    b.primary.source.to_string()
}

#[js_export]
fn sender_from_cbor(buf : crate::ByteBuffer) -> String {
    sender_from_bundle(decode_from_cbor(buf))
}

#[js_export]
fn recipient_from_bundle(b : Bundle) -> String {
    b.primary.destination.to_string()
}

#[js_export]
fn recipient_from_cbor(buf : crate::ByteBuffer) -> String {
    recipient_from_bundle(decode_from_cbor(buf))
}

#[js_export]
fn bundle_is_administrative_record(b : Bundle) -> bool {
    b.is_administrative_record()
}

#[js_export]
fn cbor_is_administrative_record(buf : crate::ByteBuffer) -> bool {
    bundle_is_administrative_record(decode_from_cbor(buf))
}
