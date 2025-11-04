use bp7::flags::*;
#[cfg(feature = "bpsec")]
use bp7::security::*;
use bp7::*;
use helpers::*;
use std::convert::TryInto;
use std::time::Duration;
//use bp7::security::AES_128_GCM;

#[test]
#[cfg(feature = "bpsec")]
fn security_data_tests() {
    let data = CanonicalData::Data(b"bla".to_vec());
    let encoded_data = serde_cbor::to_vec(&data).expect("encoding error");
    let decoded_data: CanonicalData =
        serde_cbor::from_slice(&encoded_data).expect("decoding error");
    assert_eq!(data, decoded_data);
}

fn encode_decode_test_canonical(data: CanonicalBlock) {
    let encoded_data = serde_cbor::to_vec(&data).expect("encoding error");
    let decoded_data: CanonicalBlock =
        serde_cbor::from_slice(&encoded_data).expect("decoding error");
    assert_eq!(data, decoded_data);
    //println!("{:?}", hexify(&encoded_data));
    //println!("{:?}", hexify(&decoded_data));

    //println!("{:?}", decoded_data.data());
    assert_eq!(decoded_data.data(), data.data());
}

#[test]
#[cfg(feature = "bpsec")]
fn canonical_block_tests() {
    let data =
        bp7::security::new_integrity_block(1, BlockControlFlags::empty(), b"ABCDEFG".to_vec());
    encode_decode_test_canonical(data);
}

#[test]
#[cfg(feature = "bpsec")]
fn rfc_example_tests() {
    simple_integrity_test();

    //simple_confidentiality_test();

    //multiple_sources_test();

    // Example 4 - Security Blocks with Full Scope
    // https://www.rfc-editor.org/rfc/rfc9173.html#name-example-4-security-blocks-w
    //println!("Security Blocks with Full Scope");
    // TODO
    //full_scope_test();
}

#[test]
#[cfg(feature = "bpsec")]
/// # Example 1 - Simple Integrity
///
/// ## Original Bundle
///  
/// ```
///     Block                                Block   Block
///     in Bundle                            Type    Number
/// +========================================+=======+========+
/// |  Primary Block                         |  N/A  |    0   |
/// +----------------------------------------+-------+--------+
/// |  Payload Block                         |   1   |    1   |
/// +----------------------------------------+-------+--------+
/// ```
///
/// ## Resulting Bundle
///
/// ```
/// +========================================+=======+========+
/// |  Primary Block                         |  N/A  |    0   |
/// +----------------------------------------+-------+--------+
/// |  Block Integrity Block                 |   11  |    2   |
/// |  OP(bib-integrity, target=1)           |       |        |
/// +----------------------------------------+-------+--------+
/// |  Payload Block                         |   1   |    1   |
/// +----------------------------------------+-------+--------+
/// ```
///
/// see rfc for more details:
/// https://www.rfc-editor.org/rfc/rfc9173.html#name-example-1-simple-integrity
fn simple_integrity_test() {
    println!("Simple Integrity Test");

    // Create Original bundle
    let dst = eid::EndpointID::with_ipn(1, 2).unwrap();
    let src = eid::EndpointID::with_ipn(2, 1).unwrap();
    let now = dtntime::CreationTimestamp::with_time_and_seq(0, 40);

    let primary_block = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src)
        .creation_timestamp(now)
        .lifetime(Duration::from_millis(1000000))
        .build()
        .unwrap();
    let cbor_primary = serde_cbor::to_vec(&primary_block).unwrap();
    let cbor_primary = hexify(&cbor_primary);
    let example_cbor_primary = "88070000820282010282028202018202820201820018281a000f4240";
    assert_eq!(cbor_primary, example_cbor_primary);

    let payload_block = bp7::new_payload_block(
        BlockControlFlags::empty(),
        b"Ready to generate a 32-byte payload".to_vec(),
    );
    let cbor_payload = serde_cbor::to_vec(&payload_block).unwrap();
    let cbor_payload = hexify(&cbor_payload);
    let example_cbor_payload =
        "85010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164";
    assert_eq!(cbor_payload, example_cbor_payload);

    // Create Block Integrity Block
    // Two Parts: First create IPPT then ASB

    // First Create Integrity-Protected Plaintext
    let sec_block_header: (CanonicalBlockType, u64, bp7::flags::BlockControlFlagsType) = (
        bp7::security::INTEGRITY_BLOCK,
        2,
        BlockControlFlags::empty().bits(),
    );

    let _sec_ctx_para = BibSecurityContextParameter {
        sha_variant: Some((1, HMAC_SHA_512)),
        wrapped_key: None,
        integrity_scope_flags: Some((3, 0x0000)),
    };

    let mut ippt = bp7::security::IpptBuilder::default()
        .primary_block(primary_block.clone())
        .security_header(sec_block_header)
        .scope_flags(0x0000)
        .build();
    let ippt_complete = ippt.create(&payload_block);
    let ippt_list = vec![(payload_block.block_number, &ippt_complete)];

    let cbor_ippt_complete = hexify(&ippt_complete);
    let example_ippt_complete =
        "005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164";
    //println!("{:?}", cbor_ippt_complete);

    assert_eq!(cbor_ippt_complete, example_ippt_complete);

    // Second Create Abstract Security Block
    let sec_ctx_para =
        bp7::security::BibSecurityContextParameter::new(Some((1, 7)), None, Some((3, 0x0000)));
    let mut sec_block_payload = bp7::security::IntegrityBlockBuilder::default()
        .security_targets(vec![1]) // Payload block
        .security_context_flags(1) // Parameters Present
        .security_source(EndpointID::with_ipn(2, 1).unwrap()) // ipn:2.1
        .security_context_parameters(sec_ctx_para) // 2 Parameters: HMAC 512/512 and No Additional Scope
        .build()
        .unwrap();
    let key = unhexify("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();
    let key_array: [u8; 16] = key.try_into().expect("slice with incorrect length");
    sec_block_payload.compute_hmac(key_array, ippt_list);

    // TODO: key mgmt
    // used key: 1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b
    // The Signature
    let signature = hexify(&sec_block_payload.security_results[0][0].1);
    let example_signature = "3bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1";
    assert_eq!(signature, example_signature);
    //println!("{:?}", hexify(&sec_block_payload.security_results[0][0].1));

    // The CBOR encoding of the BIB block-type-specific data field (the abstract security block):
    let canonical_payload = sec_block_payload.to_cbor();
    let cbor_canonical_payload = hexify(&canonical_payload);
    let example_canonical_payload = "810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1";
    assert_eq!(cbor_canonical_payload, example_canonical_payload);

    // The BIB
    let block_integrity_block =
        bp7::security::new_integrity_block(2, BlockControlFlags::empty(), canonical_payload);
    let cbor_bib = serde_cbor::to_vec(&block_integrity_block).unwrap();
    let cbor_bib = hexify(&cbor_bib);
    let example_bib = "850b0200005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1";
    assert_eq!(cbor_bib, example_bib);

    // The CBOR encoding of the full output bundle, with the BIB:
    let mut b = bundle::BundleBuilder::default()
        .primary(primary_block)
        .canonicals(vec![payload_block, block_integrity_block])
        .build()
        .unwrap();
    b.set_crc(crc::CRC_NO);
    b.calculate_crc();

    let cbor_bundle = hexify(&b.to_cbor());
    let example_bundle = "9f88070000820282010282028202018202820201820018281a000f4240850b0200005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff";
    assert_eq!(cbor_bundle, example_bundle);
}

#[test]
#[cfg(feature = "bpsec")]
fn no_crc_or_bib_primary_block() {
    let hex_bundle = "9f88071844008202820301820100820100821b000000b5998c982b011a000493e08506021000458202820200850704010042183485010101004454455354ff";
    let bytes = unhexify(hex_bundle);
    let bundle = crate::bundle::Bundle::try_from(bytes.unwrap().as_slice()).expect("CBOR decode");
    assert!(
        bundle.validate().is_err(),
        "Bundle had no CRC or BIB for primary block!"
    );
}
