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

    simple_confidentiality_test();

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
/// # Simple Confidentiality Test
///
/// Tests BCB (Block Confidentiality Block) with AES-256-GCM encryption/decryption
///
/// ## Test Flow:
/// 1. Create a bundle with a payload block
/// 2. Encrypt the payload using BCB with AES-256-GCM
/// 3. Decrypt the payload and verify it matches the original
///
fn simple_confidentiality_test() {
    println!("Simple Confidentiality Test");

    // Create test payload
    let plaintext_payload = b"This is a secret message!".to_vec();

    let payload_block = bp7::new_payload_block(
        BlockControlFlags::empty(),
        plaintext_payload.clone(),
    );

    // Create primary block for AAD construction
    let dst = eid::EndpointID::with_ipn(1, 2).unwrap();
    let src = eid::EndpointID::with_ipn(2, 1).unwrap();
    let now = dtntime::CreationTimestamp::with_time_and_seq(0, 40);

    let primary_block = primary::PrimaryBlockBuilder::default()
        .destination(dst)
        .source(src.clone())
        .report_to(src.clone())
        .creation_timestamp(now)
        .lifetime(Duration::from_millis(1000000))
        .build()
        .unwrap();

    // Setup BCB with AES-256-GCM
    let sec_ctx_para = BcbSecurityContextParameter::new(
        Some((1, AES_256_GCM)), // AES-256-GCM
        None,                    // No wrapped key
        Some((4, 0x0007)),       // All AAD scope flags
    );

    let mut bcb = ConfidentialityBlockBuilder::default()
        .security_targets(vec![1]) // Target the payload block
        .security_context_flags(1) // Parameters present
        .security_source(src)
        .security_context_parameters(sec_ctx_para.clone())
        .build()
        .unwrap();

    // Prepare AAD (Additional Authenticated Data)
    let sec_block_header: (CanonicalBlockType, u64, bp7::flags::BlockControlFlagsType) = (
        bp7::security::CONFIDENTIALITY_BLOCK,
        2,
        BlockControlFlags::empty().bits(),
    );

    let mut aad_builder = AadBuilder::new()
        .primary_block(primary_block.clone())
        .security_header(sec_block_header)
        .scope_flags(0x0007)
        .build();

    let aad = aad_builder.create(&payload_block);

    // Encryption parameters
    let key_256: [u8; 32] = [
        0x71, 0x69, 0x63, 0x56, 0x68, 0x7A, 0x4A, 0x59,
        0x6C, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    ];

    let iv: [u8; 12] = [
        0x5e, 0xdc, 0x5d, 0xd6, 0x09, 0xd7,
        0x8e, 0xdc, 0xb1, 0x04, 0x5d, 0x8c,
    ];

    // Encrypt the payload
    let iv_list = vec![(payload_block.block_number, iv)];
    let aad_list = vec![(payload_block.block_number, &aad)];
    let plaintext_list = vec![(payload_block.block_number, &plaintext_payload)];

    let encrypt_result = bcb.encrypt_targets(&key_256, iv_list.clone(), aad_list.clone(), plaintext_list);
    assert!(encrypt_result.is_ok(), "Encryption should succeed");

    // Verify security results were generated
    assert_eq!(bcb.security_results.len(), 1, "Should have results for one target");
    assert_eq!(bcb.security_results[0].len(), 2, "Should have auth tag and IV");

    // Extract auth tag and IV from results
    let auth_tag = &bcb.security_results[0]
        .iter()
        .find(|(id, _)| *id == 1)
        .expect("Auth tag should exist")
        .1;

    let result_iv = &bcb.security_results[0]
        .iter()
        .find(|(id, _)| *id == 2)
        .expect("IV should exist")
        .1;

    assert_eq!(result_iv.len(), 12, "IV should be 12 bytes");
    assert_eq!(auth_tag.len(), 16, "Auth tag should be 16 bytes");
    assert_eq!(result_iv.as_slice(), &iv, "IV should match");

    println!("Encryption successful");
    println!("  Auth Tag: {}", hexify(auth_tag));
    println!("  IV: {}", hexify(result_iv));

    // Now test decryption
    // In a real scenario, the ciphertext would be the encrypted payload
    // For this test, we'll simulate it by encrypting again and getting the ciphertext
    let bcb_for_decrypt = bcb.clone();

    // Simulate getting ciphertext (in reality this would come from the encrypted bundle)
    // Re-encrypt to get ciphertext
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let cipher = aes_gcm::Aes256Gcm::new((&key_256).into());
    let nonce = aes_gcm::Nonce::from_slice(&iv);

    let payload = Payload {
        msg: &plaintext_payload,
        aad: &aad,
    };

    let full_ciphertext = cipher.encrypt(nonce, payload).expect("Encryption failed");
    let ciphertext_only = full_ciphertext[..full_ciphertext.len().saturating_sub(16)].to_vec();

    // Decrypt
    let ciphertext_list = vec![(payload_block.block_number, &ciphertext_only)];
    let decrypt_result = bcb_for_decrypt.decrypt_targets(&key_256, aad_list, ciphertext_list);

    assert!(decrypt_result.is_ok(), "Decryption should succeed");

    let decrypted_plaintexts = decrypt_result.unwrap();
    assert_eq!(decrypted_plaintexts.len(), 1, "Should decrypt one target");
    assert_eq!(decrypted_plaintexts[0].0, payload_block.block_number, "Block number should match");
    assert_eq!(decrypted_plaintexts[0].1, plaintext_payload, "Decrypted plaintext should match original");

    println!("Decryption successful");
    println!("  Original:  {}", String::from_utf8_lossy(&plaintext_payload));
    println!("  Decrypted: {}", String::from_utf8_lossy(&decrypted_plaintexts[0].1));

    // Test CBOR serialization
    let canonical_bcb = bcb.to_cbor();
    println!("BCB CBOR length: {} bytes", canonical_bcb.len());

    // Create the full BCB block
    let bcb_block = bp7::security::new_confidentiality_block(
        2,
        BlockControlFlags::empty(),
        canonical_bcb,
    );

    let cbor_bcb = serde_cbor::to_vec(&bcb_block).unwrap();
    println!("Full BCB block CBOR length: {} bytes", cbor_bcb.len());
    println!("BCB block: {}", hexify(&cbor_bcb));
}
