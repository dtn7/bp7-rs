use bp7::canonical;

#[test]
fn canonical_data_tests() {
    let data = canonical::CanonicalData::Data(b"bla".to_vec());
    let encoded_data = serde_cbor::to_vec(&data).expect("encoding error");
    let decoded_data: canonical::CanonicalData =
        serde_cbor::from_slice(&encoded_data).expect("decoding error");
    assert_eq!(data, decoded_data);

    let bundleage = canonical::CanonicalData::BundleAge(23);
    let encoded_bundleage = serde_cbor::to_vec(&bundleage).expect("encoding error");
    let decoded_bundleage: canonical::CanonicalData =
        serde_cbor::from_slice(&encoded_bundleage).expect("decoding error");
    assert_eq!(bundleage, decoded_bundleage);

    let hopcount = canonical::CanonicalData::HopCount(23, 42);
    let encoded_hopcount = serde_cbor::to_vec(&hopcount).expect("encoding error");
    let decoded_hopcount: canonical::CanonicalData =
        serde_cbor::from_slice(&encoded_hopcount).expect("decoding error");
    assert_eq!(hopcount, decoded_hopcount);

    let previous = canonical::CanonicalData::PreviousNode("dtn://node1".into());
    let encoded_previous = serde_cbor::to_vec(&previous).expect("encoding error");
    let decoded_previous: canonical::CanonicalData =
        serde_cbor::from_slice(&encoded_previous).expect("decoding error");
    assert_eq!(previous, decoded_previous);
}

fn encode_decode_test_canonical(data: canonical::CanonicalBlock) {
    let encoded_data = serde_cbor::to_vec(&data).expect("encoding error");
    let decoded_data: canonical::CanonicalBlock =
        serde_cbor::from_slice(&encoded_data).expect("decoding error");
    assert_eq!(data, decoded_data);

    println!("{:?}", decoded_data.get_data());
    assert_eq!(decoded_data.get_data(), data.get_data());
    if *decoded_data.get_data() == canonical::CanonicalData::DecodingError {
        panic!("Wrong Payload");
    }
}

#[test]
fn canonical_block_tests() {
    let data = canonical::new_payload_block(0, b"ABCDEFG".to_vec());
    encode_decode_test_canonical(data);

    let data = canonical::new_hop_count_block(1, 0, 32);
    encode_decode_test_canonical(data);

    let data = canonical::new_bundle_age_block(1, 0, 0);
    encode_decode_test_canonical(data);

    let data = canonical::new_previous_node_block(1, 0, "dtn://node2".into());
    encode_decode_test_canonical(data);
}
