// separate test binary, as concurrent timestamp creation affects sequence numbers in other tests
use bp7::dtntime::CreationTimestamp;
use std::collections::HashSet;
use std::thread;

#[test]
fn test_creation_unique_across_threads() {
    let handles: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(|| {
                (0..20_000)
                    .map(|_| {
                        let ct = CreationTimestamp::now();
                        (ct.dtntime(), ct.seqno())
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    let mut seen = HashSet::new();
    for h in handles {
        for ts in h.join().unwrap() {
            assert!(seen.insert(ts), "duplicate creation timestamp {:?}", ts);
        }
    }
}
