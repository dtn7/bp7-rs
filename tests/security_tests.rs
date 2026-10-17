// all security tests require the bpsec feature
#![cfg(feature = "bpsec")]

use bp7::bpsec::*;
use bp7::flags::*;
use bp7::*;
use helpers::*;
use serde_cbor::Value;
use std::convert::TryInto;
use std::time::Duration;
//use bp7::bpsec::AES_128_GCM;

/// Expected HMAC of a security target, as byte string
fn hmac_of(ib: &IntegrityBlock, target: u64) -> &[u8] {
    match ib.result(target, EXPECTED_HMAC_RESULT) {
        Some(Value::Bytes(hmac)) => hmac,
        other => panic!("no expected HMAC for target {}: {:?}", target, other),
    }
}

#[test]
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
fn canonical_block_tests() {
    let data = bp7::bpsec::new_integrity_block(1, BlockControlFlags::empty(), b"ABCDEFG".to_vec());
    encode_decode_test_canonical(data);
}

#[test]
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
        bp7::bpsec::INTEGRITY_BLOCK,
        2,
        BlockControlFlags::empty().bits(),
    );

    let _sec_ctx_para = BibSecurityContextParameter {
        sha_variant: Some((1, HMAC_SHA_512)),
        wrapped_key: None,
        integrity_scope_flags: Some((3, 0x0000)),
    };

    let mut ippt = bp7::bpsec::IpptBuilder::default()
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
        bp7::bpsec::BibSecurityContextParameter::new(Some((1, 7)), None, Some((3, 0x0000)));
    let mut sec_block_payload = bp7::bpsec::IntegrityBlockBuilder::default()
        .security_targets(vec![1]) // Payload block
        .security_source(EndpointID::with_ipn(2, 1).unwrap()) // ipn:2.1
        .security_context_parameters(sec_ctx_para) // 2 Parameters: HMAC 512/512 and No Additional Scope
        .build()
        .unwrap();
    let key = unhexify("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();
    let key_array: [u8; 16] = key.try_into().expect("slice with incorrect length");
    sec_block_payload
        .compute_hmac(key_array, ippt_list.clone())
        .unwrap();
    assert!(verify_hmac(&sec_block_payload, &key_array, &ippt_list).unwrap());

    // TODO: key mgmt
    // used key: 1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b
    // The Signature
    let signature = hexify(hmac_of(&sec_block_payload, 1));
    let example_signature = "3bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1";
    assert_eq!(signature, example_signature);

    // The CBOR encoding of the BIB block-type-specific data field (the abstract security block):
    let canonical_payload = sec_block_payload.to_cbor();
    let cbor_canonical_payload = hexify(&canonical_payload);
    let example_canonical_payload = "810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1";
    assert_eq!(cbor_canonical_payload, example_canonical_payload);

    // The BIB
    let block_integrity_block =
        bp7::bpsec::new_integrity_block(2, BlockControlFlags::empty(), canonical_payload);
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
fn no_crc_or_bib_primary_block() {
    let hex_bundle = "9f88071844008202820301820100820100821b000000b5998c982b011a000493e08506021000458202820200850704010042183485010101004454455354ff";
    let bytes = unhexify(hex_bundle);
    let bundle = crate::bundle::Bundle::try_from(bytes.unwrap().as_slice()).expect("CBOR decode");
    assert!(
        bundle.validate().is_err(),
        "Bundle had no CRC or BIB for primary block!"
    );
}

#[test]
fn malformed_integrity_block_tests() {
    // [0], 1, 0, dtn:none, [[[1, h'010203']]]
    let valid = "8100 01 00 820100 81818201430102 03";
    assert!(IntegrityBlock::from_cbor(&unhexify(&valid.replace(' ', "")).unwrap()).is_ok());
    // empty result sets are allowed, e.g., for authentication tags in the ciphertext
    let empty_results = "8100 01 00 820100 8180";
    let ib =
        IntegrityBlock::from_cbor(&unhexify(&empty_results.replace(' ', "")).unwrap()).unwrap();
    // but a BIB without expected HMAC does not verify
    assert!(!verify_hmac(&ib, &[0; 16], &[(0, &vec![1])]).unwrap());

    for hex in [
        // only security targets
        "8100",
        // missing security results
        "8100 01 00 820100",
        // no results for security target
        "8100 01 00 820100 80",
        // no security targets
        "80 01 00 820100 80",
        // reserved security context flag
        "8100 01 02 820100 81818201430102 03",
        // parameters flagged, but missing
        "8100 01 01 820100 81818201430102 03",
        // encoded as array instead of CBOR sequence
        "86 8100 01 00 820100 80 81818201430102 03",
    ] {
        let bytes = unhexify(&hex.replace(' ', "")).unwrap();
        assert!(
            IntegrityBlock::from_cbor(&bytes).is_err(),
            "decoding {} should fail",
            hex
        );

        // a bundle carrying such a block must be rejected, not panic
        let mut bndl = bundle::new_std_payload_bundle(
            "dtn://node1/".try_into().unwrap(),
            "dtn://node2/inbox".try_into().unwrap(),
            b"ABC".to_vec(),
        );
        bndl.add_canonical_block(new_integrity_block(0, BlockControlFlags::empty(), bytes));
        assert!(bndl.decode_bibs().is_empty());
        assert!(bndl.validate().is_err());
    }
}

#[test]
fn integrity_block_sequence_decoding_tests() {
    // BIB block-type-specific data of RFC 9173 Example 1
    let rfc_bib = unhexify("810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e1").unwrap();
    let ib = IntegrityBlock::from_cbor(&rfc_bib).expect("decoding RFC example BIB");
    assert_eq!(ib.security_targets, vec![1]);
    assert_eq!(ib.security_context_id, BIB_HMAC_SHA2_ID);
    assert_eq!(ib.security_context_flags(), SEC_CONTEXT_PRESENT);
    assert_eq!(ib.security_source, EndpointID::with_ipn(2, 1).unwrap());
    let params: BibSecurityContextParameter = ib.parameters().unwrap().unwrap();
    assert_eq!(params.sha_variant, Some((1, HMAC_SHA_512)));
    assert_eq!(hmac_of(&ib, 1).len(), 64);
    assert_eq!(ib.to_cbor(), rfc_bib);

    // parameters are encoded if present and omitted otherwise
    let results = vec![
        vec![(1, Value::Bytes(vec![1, 2]))],
        vec![(1, Value::Bytes(vec![3, 4]))],
    ];
    let ib = IntegrityBlockBuilder::default()
        .security_targets(vec![0, 1])
        .security_context_parameters(BibSecurityContextParameter::default())
        .security_results(results.clone())
        .build()
        .unwrap();
    assert_eq!(IntegrityBlock::from_cbor(&ib.to_cbor()).unwrap(), ib);
    let ib = IntegrityBlockBuilder::default()
        .security_targets(vec![0, 1])
        .security_results(results)
        .build()
        .unwrap();
    let decoded = IntegrityBlock::from_cbor(&ib.to_cbor()).unwrap();
    assert_eq!(decoded.security_context_parameters, None);
    assert_eq!(decoded, ib);

    // trailing data is rejected
    let mut trailing = rfc_bib.clone();
    trailing.push(0x00);
    assert!(IntegrityBlock::from_cbor(&trailing).is_err());

    // BIBs of a decoded bundle are found
    let example_bundle = "9f88070000820282010282028202018202820201820018281a000f4240850b0200005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff";
    let bundle = Bundle::try_from(unhexify(example_bundle).unwrap().as_slice()).unwrap();
    assert_eq!(bundle.decode_bibs().len(), 1);
}

#[test]
fn bib_protected_primary_block_tests() {
    fn bundle_with_bib_targets(targets: Vec<u64>) -> Bundle {
        let mut b = bundle::new_std_payload_bundle(
            "dtn://node1/".try_into().unwrap(),
            "dtn://node2/inbox".try_into().unwrap(),
            b"ABC".to_vec(),
        );
        let results = targets
            .iter()
            .map(|_| vec![(1, Value::Bytes(vec![0; 48]))])
            .collect();
        let ib = IntegrityBlockBuilder::default()
            .security_targets(targets)
            .security_context_parameters(BibSecurityContextParameter::default())
            .security_results(results)
            .build()
            .unwrap();
        b.add_canonical_block(new_integrity_block(
            0,
            BlockControlFlags::empty(),
            ib.to_cbor(),
        ));
        b
    }

    // a BIB only covering the payload block does not protect the primary block
    assert!(bundle_with_bib_targets(vec![1]).validate().is_err());
    assert!(bundle_with_bib_targets(vec![0]).validate().is_ok());
    assert!(bundle_with_bib_targets(vec![1, 0]).validate().is_ok());
}

#[test]
fn bib_context_parameter_decoding_tests() {
    let decode =
        |hex: &str| serde_cbor::from_slice::<BibSecurityContextParameter>(&unhexify(hex).unwrap());

    // [[3, 0]]: only integrity scope flags
    let p = decode("81820300").unwrap();
    assert_eq!(
        p,
        BibSecurityContextParameter::new(None, None, Some((3, 0)))
    );
    // [[1, 7]]: only sha variant
    let p = decode("81820107").unwrap();
    assert_eq!(
        p,
        BibSecurityContextParameter::new(Some((1, 7)), None, None)
    );
    // [[3, 7], [1, 5]]: any order
    let p = decode("82820307820105").unwrap();
    assert_eq!(
        p,
        BibSecurityContextParameter::new(Some((1, 5)), None, Some((3, 7)))
    );
    // []: no parameters
    assert_eq!(
        decode("80").unwrap(),
        BibSecurityContextParameter::new(None, None, None)
    );
    // [[4, 0]]: unknown parameter
    assert!(decode("81820400").is_err());
    // [[1, h'00']]: invalid value
    assert!(decode("8182014100").is_err());

    // all parameters including a wrapped key survive a roundtrip
    let p = BibSecurityContextParameter::new(Some((1, 6)), Some((2, vec![1, 2, 3])), Some((3, 7)));
    let encoded = serde_cbor::to_vec(&p).unwrap();
    assert_eq!(
        serde_cbor::from_slice::<BibSecurityContextParameter>(&encoded).unwrap(),
        p
    );
}

#[test]
fn integrity_block_builder_tests() {
    // the parameters present flag follows the presence of parameters
    let ib = IntegrityBlockBuilder::default()
        .security_targets(vec![1])
        .build()
        .unwrap();
    assert_eq!(ib.security_context_flags(), SEC_CONTEXT_ABSENT);
    let ib = IntegrityBlockBuilder::default()
        .security_targets(vec![1])
        .security_context_parameters(BibSecurityContextParameter::default())
        .build()
        .unwrap();
    assert_eq!(ib.security_context_flags(), SEC_CONTEXT_PRESENT);
    assert_eq!(
        ib.parameters::<BibSecurityContextParameter>().unwrap(),
        Some(BibSecurityContextParameter::default())
    );

    // other security contexts can be used, e.g., for BCBs
    let asb = SecurityBlockBuilder::default()
        .security_targets(vec![1])
        .security_context_id(BCB_AES_GCM_ID)
        .parameters(vec![(4, Value::Integer(3))])
        .build()
        .unwrap();
    assert_eq!(asb.security_context_id, BCB_AES_GCM_ID);

    assert!(matches!(
        IntegrityBlockBuilder::default().build(),
        Err(BpsecError::MissingSecurityTargets)
    ));
}

#[test]
fn compute_hmac_tests() {
    let ippt_0 = vec![1u8, 2, 3];
    let ippt_2 = vec![4u8, 5, 6];
    let key = [0x1a; 16];

    // sha variant defaults to HMAC-SHA-384 without parameters
    let mut ib = IntegrityBlockBuilder::default()
        .security_targets(vec![0, 2])
        .build()
        .unwrap();
    // results follow the order of the security targets
    ib.compute_hmac(key, vec![(2, &ippt_2), (0, &ippt_0)])
        .unwrap();
    assert_eq!(ib.security_results.len(), 2);
    assert_eq!(hmac_of(&ib, 0).len(), 48);
    assert_ne!(hmac_of(&ib, 0), hmac_of(&ib, 2));
    // the result id of the expected HMAC is always 1 (RFC 9173 3.4)
    assert!(
        ib.security_results
            .iter()
            .all(|r| r.len() == 1 && r[0].0 == EXPECTED_HMAC_RESULT)
    );

    // verification
    assert!(verify_hmac(&ib, &key, &[(0, &ippt_0), (2, &ippt_2)]).unwrap());
    assert!(!verify_hmac(&ib, &key, &[(0, &ippt_2), (2, &ippt_2)]).unwrap());
    assert!(!verify_hmac(&ib, &[0x2b; 16], &[(0, &ippt_0), (2, &ippt_2)]).unwrap());
    assert!(matches!(
        verify_hmac(&ib, &key, &[(0, &ippt_0)]),
        Err(BpsecError::MissingTargetInput(2))
    ));

    // missing or unknown targets
    assert!(matches!(
        ib.compute_hmac(key, vec![(0, &ippt_0)]),
        Err(BpsecError::MissingTargetInput(2))
    ));
    assert!(matches!(
        ib.compute_hmac(key, vec![(0, &ippt_0), (2, &ippt_2), (5, &ippt_2)]),
        Err(BpsecError::UnknownTarget(5))
    ));

    // unknown sha variants are reported
    let mut ib = IntegrityBlockBuilder::default()
        .security_targets(vec![1])
        .security_context_parameters(BibSecurityContextParameter::new(Some((1, 99)), None, None))
        .build()
        .unwrap();
    assert!(matches!(
        ib.compute_hmac(key, vec![(1, &ippt_0)]),
        Err(BpsecError::Unsupported(_))
    ));
    assert!(ib.security_results.is_empty());
    // encoding with missing results does not panic
    let _ = ib.to_cbor();
}

#[test]
fn confidentiality_block_tests() {
    let params = BcbSecurityContextParameter {
        iv: Some(vec![0x5a; 12]),
        aes_variant: Some(AES_256_GCM),
        wrapped_key: None,
        aad_scope_flags: Some(0),
    };
    let bcb_for = |target: u64| {
        SecurityBlockBuilder::default()
            .security_targets(vec![target])
            .security_context_id(BCB_AES_GCM_ID)
            .security_source(EndpointID::with_ipn(2, 1).unwrap())
            .security_context_parameters(params.clone())
            .security_results(vec![vec![(
                AUTHENTICATION_TAG_RESULT,
                Value::Bytes(vec![0x42; 16]),
            )]])
            .build()
            .unwrap()
    };

    // encoded BCBs are found in a decoded bundle
    let bcb = bcb_for(1);
    let block = new_confidentiality_block(3, BlockControlFlags::empty(), bcb.to_cbor());
    assert_eq!(block.block_type, CONFIDENTIALITY_BLOCK);
    // BCBs are replicated in every fragment (RFC 9172 3.8)
    assert!(
        block
            .block_control_flags
            .contains(BlockControlFlags::BLOCK_REPLICATE)
    );
    let mut b = bundle::new_std_payload_bundle(
        "dtn://node1/".try_into().unwrap(),
        "dtn://node2/inbox".try_into().unwrap(),
        b"ABC".to_vec(),
    );
    b.set_crc(crc::CRC_32);
    b.add_canonical_block(block);
    let decoded = Bundle::try_from(b.to_cbor().as_slice()).unwrap();
    assert!(decoded.validate().is_ok());
    assert!(decoded.decode_bibs().is_empty());
    let bcbs = decoded.decode_bcbs();
    assert_eq!(bcbs, vec![bcb.clone()]);
    assert_eq!(bcbs[0].parameters().unwrap(), Some(params.clone()));
    assert_eq!(
        bcbs[0].result(1, AUTHENTICATION_TAG_RESULT),
        Some(&Value::Bytes(vec![0x42; 16]))
    );

    // BCBs can't be created with the remove block flag, but may be received with it
    let block = new_confidentiality_block(3, BlockControlFlags::BLOCK_REMOVE, bcb.to_cbor());
    assert!(
        !block
            .block_control_flags
            .contains(BlockControlFlags::BLOCK_REMOVE)
    );
    let mut removable = decoded.clone();
    for c in removable.canonicals.iter_mut() {
        if c.block_type == CONFIDENTIALITY_BLOCK {
            c.block_control_flags |= BlockControlFlags::BLOCK_REMOVE.bits();
        }
    }
    assert!(removable.validate().is_err());

    // the primary block and other BCBs must not be the target of a BCB
    for target in [0, 3] {
        let mut b = decoded.clone();
        b.add_canonical_block(new_confidentiality_block(
            0,
            BlockControlFlags::empty(),
            bcb_for(target).to_cbor(),
        ));
        assert!(b.validate().is_err(), "BCB target {}", target);
    }
}

#[test]
fn bcb_context_parameter_tests() {
    let all = BcbSecurityContextParameter {
        iv: Some(vec![1; 12]),
        aes_variant: Some(AES_128_GCM),
        wrapped_key: Some(vec![2; 24]),
        aad_scope_flags: Some(7),
    };
    assert_eq!(
        BcbSecurityContextParameter::from_parameters(&all.to_parameters()).unwrap(),
        all
    );
    assert_eq!(
        BcbSecurityContextParameter::from_parameters(&[]).unwrap(),
        BcbSecurityContextParameter::default()
    );
    assert!(matches!(
        BcbSecurityContextParameter::from_parameters(&[(IV_PARAMETER, Value::Integer(1))]),
        Err(BpsecError::InvalidParameter(IV_PARAMETER))
    ));
    assert!(matches!(
        BcbSecurityContextParameter::from_parameters(&[(9, Value::Integer(1))]),
        Err(BpsecError::UnknownParameter(9))
    ));
}

/// RFC 9173 Example 2 - Simple Confidentiality with Key Wrap
#[test]
fn rfc9173_example_2_confidentiality_test() {
    let original_bundle = "9f88070000820282010282028202018202820201820018281a000f424085010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff";
    let final_bundle = "9f88070000820282010282028202018202820201820018281a000f4240850c02010058508101020182028202018482014c5477656c76653132313231328202018203581869c411276fecddc4780df42c8a2af89296fabf34d7fae7008204008181820150efa4b5ac0108e3816c5606479801bc04850101000058233a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9aff";
    let content_key = unhexify("71776572747975696f70617364666768").unwrap();
    let kek = unhexify("6162636465666768696a6b6c6d6e6f70").unwrap();
    let iv = unhexify("5477656c7665313231323132").unwrap();
    let wrapped_key = unhexify("69c411276fecddc4780df42c8a2af89296fabf34d7fae700").unwrap();

    // AES key wrap of the content encryption key
    assert_eq!(wrap_key(&kek, &content_key).unwrap(), wrapped_key);
    assert_eq!(unwrap_key(&kek, &wrapped_key).unwrap(), content_key);
    assert!(matches!(
        unwrap_key(&content_key, &wrapped_key),
        Err(BpsecError::OperationFailed(_))
    ));

    let mut b = Bundle::try_from(unhexify(original_bundle).unwrap().as_slice()).unwrap();
    let params = BcbSecurityContextParameter {
        iv: None,
        aes_variant: Some(AES_128_GCM),
        wrapped_key: Some(wrapped_key),
        aad_scope_flags: Some(0),
    };
    // with a wrapped key, the key encryption key is given
    let bcb_number = bp7::bpsec::rfc9173::bcb::encrypt(
        &mut b,
        1,
        &kek,
        &iv,
        EndpointID::with_ipn(2, 1).unwrap(),
        params,
    )
    .unwrap();
    assert_eq!(bcb_number, 2);
    assert_eq!(hexify(&b.to_cbor()), final_bundle);

    // decrypting the RFC bundle restores the original bundle, the content encryption key
    // must be derived from the wrapped key
    let mut b = Bundle::try_from(unhexify(final_bundle).unwrap().as_slice()).unwrap();
    assert!(bp7::bpsec::rfc9173::bcb::decrypt(&mut b, 2, &content_key).is_err());
    bp7::bpsec::rfc9173::bcb::decrypt(&mut b, 2, &kek).unwrap();
    assert!(b.decode_bcbs().is_empty());
    assert_eq!(hexify(&b.to_cbor()), original_bundle);
}

#[test]
fn bcb_aes_gcm_roundtrip_tests() {
    use bp7::bpsec::rfc9173::bcb::{decrypt, encrypt};
    let key = [0x42; 32];
    let iv = [0x24; 12];
    let source = || EndpointID::with_ipn(2, 1).unwrap();
    let new_bundle = || {
        let mut b = bundle::new_std_payload_bundle(
            "dtn://node1/".try_into().unwrap(),
            "dtn://node2/inbox".try_into().unwrap(),
            b"secret payload".to_vec(),
        );
        b.add_canonical_block(new_canonical_block(
            200,
            0,
            0,
            CanonicalData::Unknown(b"secret extension".to_vec()),
        ));
        b.set_crc(crc::CRC_32);
        b
    };

    // AES-256-GCM with all AAD scope flags by default, for the payload and an extension block
    let mut b = new_bundle();
    let original = b.clone();
    let bcb_payload = encrypt(&mut b, 1, &key, &iv, source(), Default::default()).unwrap();
    let other_iv = [0x25; 12];
    let bcb_ext = encrypt(&mut b, 3, &key, &other_iv, source(), Default::default()).unwrap();
    assert_ne!(b.payload().unwrap(), original.payload().unwrap());
    let payload_block = b.extension_block_by_type(PAYLOAD_BLOCK).unwrap();
    assert_eq!(payload_block.crc, crc::CrcValue::CrcNo);

    let mut received = Bundle::try_from(b.to_cbor().as_slice()).unwrap();
    assert!(received.validate().is_ok());
    assert_eq!(received.decode_bcbs().len(), 2);

    // failed decryption leaves the bundle unchanged
    let before = received.clone();
    assert!(matches!(
        decrypt(&mut received, bcb_payload, &[0x43; 32]),
        Err(BpsecError::OperationFailed(_))
    ));
    assert_eq!(received, before);
    // the primary block is authenticated
    let mut tampered = received.clone();
    tampered.primary.lifetime += Duration::from_secs(1);
    assert!(decrypt(&mut tampered, bcb_payload, &key).is_err());

    decrypt(&mut received, bcb_payload, &key).unwrap();
    decrypt(&mut received, bcb_ext, &key).unwrap();
    assert!(received.decode_bcbs().is_empty());
    assert_eq!(received.payload(), original.payload());
    assert_eq!(
        received.extension_block_by_type(200).unwrap().data(),
        &CanonicalData::Unknown(b"secret extension".to_vec())
    );
}

#[test]
fn bcb_aes_gcm_error_tests() {
    use bp7::bpsec::rfc9173::bcb::{decrypt, encrypt};
    let key = [0x42; 32];
    let iv = [0x24; 12];
    let source = || EndpointID::with_ipn(2, 1).unwrap();
    let mut b = bundle::new_std_payload_bundle(
        "dtn://node1/".try_into().unwrap(),
        "dtn://node2/inbox".try_into().unwrap(),
        b"ABC".to_vec(),
    );
    let params_128 = BcbSecurityContextParameter {
        aes_variant: Some(AES_128_GCM),
        ..Default::default()
    };

    assert!(matches!(
        encrypt(&mut b, 1, &key, &iv, source(), params_128),
        Err(BpsecError::InvalidKey(_))
    ));
    // IVs must have 8 to 16 bytes
    for iv_len in [7, 17] {
        assert!(matches!(
            encrypt(
                &mut b,
                1,
                &key,
                &vec![0; iv_len],
                source(),
                Default::default()
            ),
            Err(BpsecError::InvalidParameter(IV_PARAMETER))
        ));
    }
    let reserved_flags = BcbSecurityContextParameter {
        aad_scope_flags: Some(0x0008),
        ..Default::default()
    };
    assert!(matches!(
        encrypt(&mut b, 1, &key, &iv, source(), reserved_flags),
        Err(BpsecError::InvalidParameter(AAD_SCOPE_FLAGS_PARAMETER))
    ));
    assert!(matches!(
        encrypt(&mut b, 9, &key, &iv, source(), Default::default()),
        Err(BpsecError::MissingBlock(9))
    ));
    // the hop count block could not be decoded anymore
    assert!(matches!(
        encrypt(&mut b, 2, &key, &iv, source(), Default::default()),
        Err(BpsecError::Unsupported(_))
    ));
    let unchanged = b.clone();

    // BCBs must not be encrypted
    let bcb = encrypt(&mut b, 1, &key, &iv, source(), Default::default()).unwrap();
    assert!(matches!(
        encrypt(&mut b, bcb, &key, &[0x25; 12], source(), Default::default()),
        Err(BpsecError::InvalidTarget(..))
    ));
    assert_ne!(b, unchanged);

    assert!(matches!(
        decrypt(&mut b, 9, &key),
        Err(BpsecError::MissingBlock(9))
    ));
    // BCBs of other security contexts or without IV are not decrypted
    for asb in [
        SecurityBlockBuilder::default()
            .security_targets(vec![1])
            .security_context_id(7)
            .security_results(vec![vec![(1, Value::Bytes(vec![0; 16]))]])
            .build()
            .unwrap(),
        SecurityBlockBuilder::default()
            .security_targets(vec![1])
            .security_context_id(BCB_AES_GCM_ID)
            .security_results(vec![vec![(1, Value::Bytes(vec![0; 16]))]])
            .build()
            .unwrap(),
    ] {
        let mut b = unchanged.clone();
        b.add_canonical_block(new_confidentiality_block(
            0,
            BlockControlFlags::empty(),
            asb.to_cbor(),
        ));
        let number = b
            .extension_block_by_type(CONFIDENTIALITY_BLOCK)
            .unwrap()
            .block_number;
        assert!(decrypt(&mut b, number, &key).is_err());
    }
}

#[test]
fn bib_wrapped_key_tests() {
    let kek = [0x6b; 32];
    let hmac_key = [0x1a; 16];
    let ippt = vec![1u8, 2, 3];

    let params = BibSecurityContextParameter::new(
        Some((1, HMAC_SHA_256)),
        Some((2, wrap_key(&kek, &hmac_key).unwrap())),
        None,
    );
    let mut ib = IntegrityBlockBuilder::default()
        .security_targets(vec![1])
        .security_context_parameters(params)
        .build()
        .unwrap();
    // with a wrapped key, the key encryption key is given
    ib.compute_hmac(kek, vec![(1, &ippt)]).unwrap();
    assert!(verify_hmac(&ib, &kek, &[(1, &ippt)]).unwrap());
    assert!(verify_hmac(&ib, &hmac_key, &[(1, &ippt)]).is_err());

    // the HMAC is calculated with the unwrapped key
    let mut plain = IntegrityBlockBuilder::default()
        .security_targets(vec![1])
        .security_context_parameters(BibSecurityContextParameter::new(
            Some((1, HMAC_SHA_256)),
            None,
            None,
        ))
        .build()
        .unwrap();
    plain.compute_hmac(hmac_key, vec![(1, &ippt)]).unwrap();
    assert_eq!(hmac_of(&plain, 1), hmac_of(&ib, 1));

    // invalid key encryption keys and keys to wrap
    assert!(matches!(
        wrap_key(&[0; 10], &hmac_key),
        Err(BpsecError::InvalidKey(_))
    ));
    assert!(matches!(
        wrap_key(&kek, &[0; 12]),
        Err(BpsecError::InvalidKey(_))
    ));
}

#[test]
fn bcb_aes_gcm_tag_in_ciphertext_test() {
    use bp7::bpsec::rfc9173::bcb::{decrypt, encrypt};
    let key = [0x42; 16];
    let params = BcbSecurityContextParameter {
        aes_variant: Some(AES_128_GCM),
        ..Default::default()
    };
    let mut b = bundle::new_std_payload_bundle(
        "dtn://node1/".try_into().unwrap(),
        "dtn://node2/inbox".try_into().unwrap(),
        b"secret payload".to_vec(),
    );
    let original = b.clone();
    let bcb_number = encrypt(&mut b, 1, &key, &[0x24; 12], EndpointID::none(), params).unwrap();

    // move the authentication tag from the results to the end of the ciphertext
    let bcb_block = b
        .canonicals
        .iter_mut()
        .find(|c| c.block_number == bcb_number)
        .unwrap();
    let mut bcb = match bcb_block.data() {
        CanonicalData::Unknown(data) => ConfidentialityBlock::from_cbor(data).unwrap(),
        _ => panic!("no BCB"),
    };
    let tag = match bcb.result(1, AUTHENTICATION_TAG_RESULT) {
        Some(Value::Bytes(tag)) => tag.clone(),
        _ => panic!("no tag"),
    };
    bcb.security_results = vec![vec![]];
    bcb_block.set_data(CanonicalData::Unknown(bcb.to_cbor()));
    let payload = b
        .canonicals
        .iter_mut()
        .find(|c| c.block_number == 1)
        .unwrap();
    let mut ciphertext = payload.payload_data().unwrap().clone();
    ciphertext.extend(tag);
    payload.set_data(CanonicalData::Data(ciphertext));

    let mut received = Bundle::try_from(b.to_cbor().as_slice()).unwrap();
    let mut tampered = received.clone();
    decrypt(&mut received, bcb_number, &key).unwrap();
    assert_eq!(received.payload(), original.payload());

    // the appended tag is authenticated
    let payload = tampered
        .canonicals
        .iter_mut()
        .find(|c| c.block_number == 1)
        .unwrap();
    let mut data = payload.payload_data().unwrap().clone();
    *data.last_mut().unwrap() ^= 1;
    payload.set_data(CanonicalData::Data(data));
    assert!(decrypt(&mut tampered, bcb_number, &key).is_err());
}

#[test]
fn ippt_tests() {
    let primary_block = primary::PrimaryBlockBuilder::default()
        .destination(EndpointID::with_ipn(1, 2).unwrap())
        .source(EndpointID::with_ipn(2, 1).unwrap())
        .report_to(EndpointID::with_ipn(2, 1).unwrap())
        .creation_timestamp(dtntime::CreationTimestamp::with_time_and_seq(0, 40))
        .lifetime(Duration::from_millis(1000000))
        .build()
        .unwrap();
    let payload_block = bp7::new_payload_block(
        BlockControlFlags::empty(),
        b"Ready to generate a 32-byte payload".to_vec(),
    );
    let age_block = new_bundle_age_block(2, BlockControlFlags::empty(), 300);
    let bib_header = (INTEGRITY_BLOCK, 3, 0);

    // RFC 9173 example 3: primary block and bundle age block, no additional scope
    let ippt = integrity_protected_plaintext(
        0,
        &primary_block,
        IpptTarget::PrimaryBlock(&primary_block),
        bib_header,
    );
    assert_eq!(
        hexify(&ippt),
        "00581c88070000820282010282028202018202820201820018281a000f4240"
    );
    let ippt =
        integrity_protected_plaintext(0, &primary_block, IpptTarget::Block(&age_block), bib_header);
    assert_eq!(hexify(&ippt), "004319012c");
    // the primary block and target header are not added again for the primary block
    let ippt = integrity_protected_plaintext(
        7,
        &primary_block,
        IpptTarget::PrimaryBlock(&primary_block),
        bib_header,
    );
    assert_eq!(
        hexify(&ippt),
        "070b0300581c88070000820282010282028202018202820201820018281a000f4240"
    );

    // RFC 9173 example 4: payload block with all scope flags
    let ippt = integrity_protected_plaintext(
        7,
        &primary_block,
        IpptTarget::Block(&payload_block),
        bib_header,
    );
    assert_eq!(
        hexify(&ippt),
        concat!(
            "0788070000820282010282028202018202820201820018281a000f4240",
            "010100",
            "0b0300",
            "5823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164"
        )
    );
    // the builder creates the same IPPT
    let mut builder_ippt = IpptBuilder::default()
        .scope_flags(7)
        .primary_block(primary_block.clone())
        .security_header(bib_header)
        .build();
    assert_eq!(builder_ippt.create(&payload_block), ippt);

    // the block-type-specific data of other blocks is wrapped once as byte string
    let unknown_block = new_canonical_block(200, 4, 0, CanonicalData::Unknown(vec![1, 2, 3]));
    let ippt = integrity_protected_plaintext(
        0,
        &primary_block,
        IpptTarget::Block(&unknown_block),
        bib_header,
    );
    assert_eq!(hexify(&ippt), "0043010203");
}

const RFC_ORIGINAL_BUNDLE: &str = "9f88070000820282010282028202018202820201820018281a000f424085010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff";

#[test]
fn rfc9173_example_1_sign_verify_test() {
    use bp7::bpsec::rfc9173::bib::{sign, verify};
    let final_bundle = "9f88070000820282010282028202018202820201820018281a000f4240850b0200005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff";
    let key = unhexify("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();

    let mut b = Bundle::try_from(unhexify(RFC_ORIGINAL_BUNDLE).unwrap().as_slice()).unwrap();
    let params = BibSecurityContextParameter::new(Some((1, HMAC_SHA_512)), None, Some((3, 0)));
    let bib = sign(
        &mut b,
        &[1],
        &key,
        EndpointID::with_ipn(2, 1).unwrap(),
        params,
    )
    .unwrap();
    assert_eq!(bib, 2);
    assert_eq!(hexify(&b.to_cbor()), final_bundle);

    let mut received = Bundle::try_from(unhexify(final_bundle).unwrap().as_slice()).unwrap();
    assert!(verify(&received, 2, &key).unwrap());
    assert!(!verify(&received, 2, &[0x2b; 16]).unwrap());
    received.set_payload(b"Ready to generate a 32-byte paylaod".to_vec());
    assert!(!verify(&received, 2, &key).unwrap());
}

/// RFC 9173 Example 3 - Security Blocks from Multiple Sources
#[test]
fn rfc9173_example_3_test() {
    use bp7::bpsec::rfc9173::{bcb, bib};
    let original_bundle = "9f88070000820282010282028202018202820201820018281a000f424085070200004319012c85010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff";
    let final_bundle = "9f88070000820282010282028202018202820201820018281a000f4240850b030000585c8200020101820282030082820105820300828182015820cac6ce8e4c5dae57988b757e49a6dd1431dc04763541b2845098265bc817241b81820158203ed614c0d97f49b3633627779aa18a338d212bf3c92b97759d9739cd50725596850c04010058348101020182028202018382014c5477656c76653132313231328202018204008181820150efa4b5ac0108e3816c5606479801bc0485070200004319012c850101000058233a09c1e63fe23a7f66a59c7303837241e070b02619fc59c5214a22f08cd70795e73e9aff";
    let hmac_key = unhexify("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();
    let content_key = unhexify("71776572747975696f70617364666768").unwrap();
    let iv = unhexify("5477656c7665313231323132").unwrap();

    // BIB over primary block and bundle age block, BCB over the payload
    let mut b = Bundle::try_from(unhexify(original_bundle).unwrap().as_slice()).unwrap();
    let bib_params = BibSecurityContextParameter::new(Some((1, HMAC_SHA_256)), None, Some((3, 0)));
    let bib_number = bib::sign(
        &mut b,
        &[0, 2],
        &hmac_key,
        EndpointID::with_ipn(3, 0).unwrap(),
        bib_params,
    )
    .unwrap();
    assert_eq!(bib_number, 3);
    let bcb_params = BcbSecurityContextParameter {
        aes_variant: Some(AES_128_GCM),
        aad_scope_flags: Some(0),
        ..Default::default()
    };
    let bcb_number = bcb::encrypt(
        &mut b,
        1,
        &content_key,
        &iv,
        EndpointID::with_ipn(2, 1).unwrap(),
        bcb_params,
    )
    .unwrap();
    assert_eq!(bcb_number, 4);
    assert_eq!(hexify(&b.to_cbor()), final_bundle);

    // and back
    let mut b = Bundle::try_from(unhexify(final_bundle).unwrap().as_slice()).unwrap();
    assert!(bib::verify(&b, 3, &hmac_key).unwrap());
    bcb::decrypt(&mut b, 4, &content_key).unwrap();
    assert!(bib::verify(&b, 3, &hmac_key).unwrap());
    assert_eq!(
        b.payload().unwrap(),
        &b"Ready to generate a 32-byte payload".to_vec()
    );
    // the primary block is a security target
    b.primary.lifetime += Duration::from_millis(1);
    assert!(!bib::verify(&b, 3, &hmac_key).unwrap());
}

/// RFC 9173 Example 4 - Security Blocks with Full Scope, verified after decryption
#[test]
fn rfc9173_example_4_test() {
    use bp7::bpsec::rfc9173::{bcb, bib};
    let final_bundle = "9f88070000820282010282028202018202820201820018281a000f4240850b0300005846438ed6208eb1c1ffb94d952175167df0902902064a2983910c4fb2340790bf420a7d1921d5bf7c4721e02ab87a93ab1e0b75cf62e4948727c8b5dae46ed2af05439b88029191850c0201005849820301020182028202018382014c5477656c76653132313231328202038204078281820150220ffc45c8a901999ecc60991dd78b2981820150d2c51cb2481792dae8b21d848cede99b8501010000582390eab6457593379298a8724e16e61f837488e127212b59ac91f8a86287b7d07630a122ff";
    let hmac_key = unhexify("1a2b1a2b1a2b1a2b1a2b1a2b1a2b1a2b").unwrap();
    let content_key =
        unhexify("71776572747975696f7061736466676871776572747975696f70617364666768").unwrap();

    let mut b = Bundle::try_from(unhexify(final_bundle).unwrap().as_slice()).unwrap();
    // the BIB is encrypted and can't be verified before decryption
    assert!(bib::verify(&b, 3, &hmac_key).is_err());
    bcb::decrypt(&mut b, 2, &content_key).unwrap();
    assert!(bib::verify(&b, 3, &hmac_key).unwrap());
    assert_eq!(
        hexify(&b.to_cbor()),
        "9f88070000820282010282028202018202820201820018281a000f4240850b030000584681010101820282020182820106820307818182015830f75fe4c37f76f046165855bd5ff72fbfd4e3a64b4695c40e2b787da005ae819f0a2e30a2e8b325527de8aefb52e73d7185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff"
    );
}

#[test]
fn bib_sign_error_tests() {
    use bp7::bpsec::rfc9173::bib::{sign, verify};
    let key = [0x1a; 16];
    let mut b = bundle::new_std_payload_bundle(
        "dtn://node1/".try_into().unwrap(),
        "dtn://node2/inbox".try_into().unwrap(),
        b"ABC".to_vec(),
    );
    b.set_crc(crc::CRC_32);
    let source = || EndpointID::with_ipn(2, 1).unwrap();
    assert!(matches!(
        sign(&mut b, &[], &key, source(), Default::default()),
        Err(BpsecError::MissingSecurityTargets)
    ));
    assert!(matches!(
        sign(&mut b, &[9], &key, source(), Default::default()),
        Err(BpsecError::MissingBlock(9))
    ));
    assert!(matches!(
        sign(&mut b, &[1, 1], &key, source(), Default::default()),
        Err(BpsecError::InvalidTarget(1, _))
    ));
    let bib = sign(&mut b, &[0, 1], &key, source(), Default::default()).unwrap();
    assert!(verify(&b, bib, &key).unwrap());
    // the primary block has no CRC as target of the BIB, but is protected by it
    assert_eq!(b.primary.crc, crc::CrcValue::CrcNo);
    let received = Bundle::try_from(b.to_cbor().as_slice()).unwrap();
    assert!(received.validate().is_ok(), "{:?}", received.validate());
    assert!(verify(&received, bib, &key).unwrap());
    // BIBs must not target security blocks
    assert!(matches!(
        sign(&mut b, &[bib], &key, source(), Default::default()),
        Err(BpsecError::InvalidTarget(..))
    ));
    assert!(matches!(
        verify(&b, 1, &key),
        Err(BpsecError::MissingBlock(1))
    ));
}

#[test]
fn bcb_aes_gcm_iv_length_tests() {
    use bp7::bpsec::rfc9173::bcb::{decrypt, encrypt};
    for (variant, key) in [(AES_128_GCM, vec![0x42; 16]), (AES_256_GCM, vec![0x42; 32])] {
        let mut ciphertexts = Vec::new();
        for iv_len in 8..=16 {
            let mut b = bundle::new_std_payload_bundle(
                "dtn://node1/".try_into().unwrap(),
                "dtn://node2/inbox".try_into().unwrap(),
                b"secret payload".to_vec(),
            );
            let original = b.clone();
            let params = BcbSecurityContextParameter {
                aes_variant: Some(variant),
                ..Default::default()
            };
            let iv: Vec<u8> = (0..iv_len as u8).collect();
            let bcb = encrypt(&mut b, 1, &key, &iv, EndpointID::none(), params).unwrap();
            ciphertexts.push(b.payload().unwrap().clone());

            let mut received = Bundle::try_from(b.to_cbor().as_slice()).unwrap();
            decrypt(&mut received, bcb, &key).unwrap();
            assert_eq!(
                received.payload(),
                original.payload(),
                "IV of {} bytes",
                iv_len
            );
        }
        // every IV length results in a different ciphertext
        ciphertexts.sort();
        ciphertexts.dedup();
        assert_eq!(ciphertexts.len(), 9);
    }
}

#[test]
fn reserved_integrity_scope_flags_tests() {
    use bp7::bpsec::rfc9173::bib::sign;
    let key = [0x1a; 16];
    let mut b = bundle::new_std_payload_bundle(
        "dtn://node1/".try_into().unwrap(),
        "dtn://node2/inbox".try_into().unwrap(),
        b"ABC".to_vec(),
    );
    b.set_crc(crc::CRC_32);
    // failed signing leaves the bundle and its CRCs unchanged
    let unchanged = b.clone();
    let unsupported = BibSecurityContextParameter::new(Some((1, 99)), None, None);
    assert!(sign(&mut b, &[0, 1], &key, EndpointID::none(), unsupported).is_err());
    let wrapped = BibSecurityContextParameter::new(None, Some((2, vec![0; 24])), None);
    assert!(sign(&mut b, &[0, 1], &key, EndpointID::none(), wrapped).is_err());
    for flags in [0x0008, 0x0080, 0x0100, 0x8000] {
        let params = BibSecurityContextParameter::new(None, None, Some((3, flags)));
        assert!(matches!(
            sign(&mut b, &[0, 1], &key, EndpointID::none(), params),
            Err(BpsecError::InvalidParameter(
                INTEGRITY_SCOPE_FLAGS_PARAMETER
            ))
        ));
    }
    assert_eq!(b, unchanged);

    // received BIBs with such flags are verified, the flags are not part of the IPPT
    let ippt = vec![1u8, 2, 3];
    let mut ib = IntegrityBlockBuilder::default()
        .security_targets(vec![1])
        .security_context_parameters(BibSecurityContextParameter::new(None, None, Some((3, 7))))
        .build()
        .unwrap();
    ib.compute_hmac(key, vec![(1, &ippt)]).unwrap();
    ib.set_parameters(&BibSecurityContextParameter::new(
        None,
        None,
        Some((3, 0x0107)),
    ));
    assert!(verify_hmac(&ib, &key, &[(1, &ippt)]).unwrap());
    assert!(matches!(
        ib.compute_hmac(key, vec![(1, &ippt)]),
        Err(BpsecError::InvalidParameter(
            INTEGRITY_SCOPE_FLAGS_PARAMETER
        ))
    ));
}
