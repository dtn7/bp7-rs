use bp7::dtntime::CreationTimestamp;
use std::thread::sleep;
use std::time::Duration;

#[test]
fn test_creation_with_delay() {
    let ct1 = CreationTimestamp::now();
    sleep(Duration::from_millis(50));
    let ct2 = CreationTimestamp::now();
    assert_eq!(ct1.seqno(), ct2.seqno());
    assert_ne!(ct1.dtntime(), ct2.dtntime());

    sleep(Duration::from_millis(1100));
    let ct3 = CreationTimestamp::now();
    let ct4 = CreationTimestamp::now();
    assert_eq!(ct3.seqno(), 0);
    assert_eq!(ct4.seqno(), 1);

    assert_eq!(ct3.dtntime(), ct4.dtntime());
}
