use bp7::primary;

#[test]
fn test_lifetime() {
    let p1 = primary::new_primary_block(
        "dtn:node1",
        "dtn:node2",
        bp7::dtntime::CreationTimestamp::now(),
        10_000_000,
    );
    assert!(!p1.is_lifetime_exceeded());

    let p2 = primary::new_primary_block(
        "dtn:node1",
        "dtn:node2",
        bp7::dtntime::CreationTimestamp::with_time_and_seq(0, 0),
        10,
    );
    assert!(!p2.is_lifetime_exceeded());

    let p2 = primary::new_primary_block(
        "dtn:node1",
        "dtn:node2",
        bp7::dtntime::CreationTimestamp::with_time_and_seq(1, 0),
        10_000_000,
    );
    assert!(p2.is_lifetime_exceeded());
}
