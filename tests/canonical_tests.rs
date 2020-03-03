use bp7::*;

#[test]
fn canonical_data_tests() {
    let data = CanonicalData::Data(b"bla".to_vec());
    let encoded_data = serde_cbor::to_vec(&data).expect("encoding error");
    let decoded_data: CanonicalData =
        serde_cbor::from_slice(&encoded_data).expect("decoding error");
    assert_eq!(data, decoded_data);

    let bundleage = dbg!(CanonicalData::BundleAge(23));
    let encoded_bundleage = serde_cbor::to_vec(&bundleage).expect("encoding error");
    let decoded_bundleage: CanonicalData =
        serde_cbor::from_slice(&encoded_bundleage).expect("decoding error");
    assert_eq!(bundleage, decoded_bundleage);

    let hopcount = CanonicalData::HopCount(23, 42);
    let encoded_hopcount = serde_cbor::to_vec(&hopcount).expect("encoding error");
    let decoded_hopcount: CanonicalData =
        serde_cbor::from_slice(&encoded_hopcount).expect("decoding error");
    assert_eq!(hopcount, decoded_hopcount);

    let previous = CanonicalData::PreviousNode("dtn://node1".into());
    let encoded_previous = serde_cbor::to_vec(&previous).expect("encoding error");
    let decoded_previous: CanonicalData =
        serde_cbor::from_slice(&encoded_previous).expect("decoding error");
    assert_eq!(previous, decoded_previous);
}

fn encode_decode_test_canonical(data: CanonicalBlock) {
    let encoded_data = serde_cbor::to_vec(&data).expect("encoding error");
    let decoded_data: CanonicalBlock =
        serde_cbor::from_slice(&encoded_data).expect("decoding error");
    assert_eq!(data, decoded_data);

    println!("{:?}", decoded_data.data());
    assert_eq!(decoded_data.data(), data.data());
    if *decoded_data.data() == CanonicalData::DecodingError {
        panic!("Wrong Payload");
    }
}

#[test]
fn canonical_block_tests() {
    let data = new_payload_block(0, b"ABCDEFG".to_vec());
    encode_decode_test_canonical(data);

    let data = new_hop_count_block(1, 0, 32);
    encode_decode_test_canonical(data);

    let data = new_bundle_age_block(1, 0, 0);
    encode_decode_test_canonical(data);

    let data = new_previous_node_block(1, 0, "dtn://node2".into());
    encode_decode_test_canonical(data);
}

#[test]
fn hopcount_tests() {
    let mut block = new_hop_count_block(1, 0, 1);

    assert_eq!(block.block_type, bp7::HOP_COUNT_BLOCK);
    assert_eq!(block.hop_count_exceeded(), false);

    if let CanonicalData::HopCount(hc_limit, hc_count) = block.data() {
        assert!(*hc_limit == 1);
        assert!(*hc_count == 0);
    } else {
        panic!("Not a hop count block!");
    }

    assert_eq!(block.hop_count_increase(), true);
    if let Some((hc_limit, hc_count)) = block.hop_count_get() {
        assert!(hc_limit == 1);
        assert!(hc_count == 1);
    } else {
        panic!("Not a hop count block!");
    }

    assert_eq!(block.hop_count_increase(), true);
    assert_eq!(block.hop_count_exceeded(), true);

    let mut wrong_block = new_bundle_age_block(1, 0, 0);
    assert_eq!(wrong_block.hop_count_increase(), false);
    assert_eq!(wrong_block.hop_count_exceeded(), false);
    assert_eq!(wrong_block.hop_count_get(), None);
}

#[test]
fn previousnode_tests() {
    let mut block = new_previous_node_block(1, 0, "dtn://node1".into());

    assert_eq!(block.block_type, bp7::PREVIOUS_NODE_BLOCK);
    if let Some(eid) = block.previous_node_get() {
        assert_eq!(*eid, EndpointID::from("dtn://node1"));
    } else {
        panic!("Not a previous node block!");
    }

    assert!(block.previous_node_update("dtn://node2".into()));

    if let Some(eid) = block.previous_node_get() {
        assert_eq!(*eid, EndpointID::from("dtn://node2"));
    } else {
        panic!("Not a previous node block!");
    }

    let mut wrong_block = new_bundle_age_block(1, 0, 0);
    assert_eq!(wrong_block.previous_node_get(), None);
    assert_eq!(
        wrong_block.previous_node_update("dtn://node2".into()),
        false
    );
}

#[test]
fn bundleage_tests() {
    let mut block = new_bundle_age_block(1, 0, 0);

    assert_eq!(block.block_type, bp7::BUNDLE_AGE_BLOCK);
    if let Some(age) = block.bundle_age_get() {
        assert_eq!(age, 0);
    } else {
        panic!("Not a bundle age block!");
    }

    assert!(block.bundle_age_update(200));

    if let Some(age) = block.bundle_age_get() {
        assert_eq!(age, 200);
    } else {
        panic!("Not a bundle age block!");
    }

    let mut wrong_block = new_hop_count_block(1, 0, 1);
    assert_eq!(wrong_block.bundle_age_get(), None);
    assert_eq!(wrong_block.bundle_age_update(2342), false);
}
