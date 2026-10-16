use bp7::helpers::{hexify, unhexify};

#[test]
fn unhexify_tests() {
    assert_eq!(unhexify("").unwrap(), Vec::<u8>::new());
    assert_eq!(unhexify("00ff0aA0").unwrap(), vec![0x00, 0xff, 0x0a, 0xa0]);
    let bytes: Vec<u8> = (0..=255).collect();
    assert_eq!(unhexify(&hexify(&bytes)).unwrap(), bytes);

    // invalid input is reported, not panicking
    for invalid in ["0", "abc", "zz", "+a+b", "-1", "ä0", "0ä", "aä", "€"] {
        assert!(unhexify(invalid).is_err(), "{}", invalid);
    }
}
