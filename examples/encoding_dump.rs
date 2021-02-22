use bp7::crc::CrcBlock;
use bp7::{
    bundle, canonical, crc, dtntime, eid,
    helpers::{ser_dump, vec_dump},
    primary, Bundle, ByteBuffer, EndpointID,
};
use std::convert::TryFrom;
use std::convert::TryInto;

fn main() {
    // Endpoint ID
    let hr = "dtn://node1/test";
    let eid: EndpointID = hr.try_into().unwrap();
    ser_dump(&eid, hr);

    let hr = "ipn:23.42";
    let eid: EndpointID = hr.try_into().unwrap();
    ser_dump(&eid, hr);

    let eid = EndpointID::none();
    ser_dump(&eid, &eid.to_string());

    // Creation Timestamp

    let ts = bp7::CreationTimestamp::now();
    ser_dump(&ts, &ts.to_string());

    // Canonical Blocks

    let cblock = canonical::new_payload_block(0, b"ABC".to_vec());
    ser_dump(
        &cblock,
        "payload block with no flags and `'ABC'` as content, no crc",
    );

    let cblock = canonical::new_hop_count_block(1, 0, 32);
    ser_dump(
        &cblock,
        "hop count block with no flags, block number 1 and hop limit = 32, no crc",
    );

    let cblock = canonical::new_bundle_age_block(2, 0, 1234);
    ser_dump(
        &cblock,
        "bundle age block with no flags, block number 2 and age = 1234us, no crc",
    );

    let cblock = canonical::new_previous_node_block(3, 0, "dtn://n1".try_into().unwrap());
    ser_dump(
        &cblock,
        "previous node block with no flags, block number 3 and prev_node = `dtn://n1`, no crc",
    );

    // Primary block

    let pblock = primary::new_primary_block(
        "dtn://n2/inbox".try_into().unwrap(),
        "dtn://n1/".try_into().unwrap(),
        bp7::CreationTimestamp::with_time_and_seq(2342, 2),
        std::time::Duration::from_secs(60),
    );
    ser_dump(
        &pblock,
        "primary block with no flags, no fragmentation, lifetime of `60s`, creation timestamp `[2342, 2]` from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, no crc",
    );

    let mut pblock = primary::new_primary_block(
        "dtn://n2/inbox".try_into().unwrap(),
        "dtn://n1/".try_into().unwrap(),
        bp7::CreationTimestamp::with_time_and_seq(2342, 2),
        std::time::Duration::from_secs(60),
    );
    pblock.set_crc_type(crc::CRC_16);
    pblock.update_crc();
    ser_dump(
        &pblock,
        "primary block with no flags, no fragmentation, lifetime of `60s`, creation timestamp `[2342, 2]` from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, crc16",
    );

    let mut pblock = primary::new_primary_block(
        "dtn://n2/inbox".try_into().unwrap(),
        "dtn://n1/".try_into().unwrap(),
        bp7::CreationTimestamp::with_time_and_seq(2342, 2),
        std::time::Duration::from_secs(60),
    );
    pblock.set_crc_type(crc::CRC_32);
    pblock.update_crc();
    ser_dump(
        &pblock,
        "primary block with no flags, no fragmentation, lifetime of `60s`, creation timestamp `[2342, 2]` from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, crc32",
    );

    // Complete Bundle

    let mut bndl = bp7::bundle::new_std_payload_bundle(
        "dtn://n1/".try_into().unwrap(),
        "dtn://n2/inbox".try_into().unwrap(),
        b"ABC".to_vec(),
    );
    vec_dump(
        &bndl.clone(),
        bndl.to_cbor(),
        "bundle with no flags, no fragmentation, lifetime of `60 * 60s`, creation timestamp now from `dtn://n1` to `dtn://n2/inbox` with reporting to `dtn://n1`, payload `'ABC'` and hop count block with 32 hop limit, no crc",
    );
}
