mod common;
use common::Fixture;
use holon_vc::presentations::{self, SqliteReplay};
#[tokio::test]
async fn signed_unsigned_mismatch_and_persistent_replay() {
    let f = Fixture::new().await;
    let vc = f.issue().await;
    let unsigned = presentations::create(&f.app, vec![vc.clone()], None, None, None, None, None)
        .await
        .unwrap();
    let mut replay = SqliteReplay::open(&f.app.root).unwrap();
    let r = presentations::verify(&f.app, &unsigned, None, None, &[], &mut replay).await;
    assert!(r.accepted("authentic-assertion"), "{r:?}");
    assert!(!r.holder_authenticated);
    let mut s = f.suite.clone();
    s.purpose = "authentication".into();
    let c = "verifier-random-nonce-123456";
    let d = "verifier.example";
    let signed = presentations::create(
        &f.app,
        vec![vc],
        Some(&s.controller),
        Some((&s, &f.key)),
        Some(c),
        Some(d),
        None,
    )
    .await
    .unwrap();
    for (challenge, domain) in [("wrong-verifier-nonce-123", d), (c, "wrong.example")] {
        let r = presentations::verify(
            &f.app,
            &signed,
            Some(challenge),
            Some(domain),
            &[],
            &mut replay,
        )
        .await;
        assert_eq!(r.decision, "rejected");
        assert!(!r.holder_authenticated);
    }
    let r = presentations::verify(&f.app, &signed, Some(c), Some(d), &[], &mut replay).await;
    assert!(r.accepted("authentic-assertion"), "{r:?}");
    assert!(r.holder_authenticated);
    drop(replay);
    let mut replay = SqliteReplay::open(&f.app.root).unwrap();
    let r = presentations::verify(&f.app, &signed, Some(c), Some(d), &[], &mut replay).await;
    assert!(r.errors.contains(&"REPLAYED".into()), "{r:?}");
    assert!(!r.holder_authenticated);
}
#[test]
fn atomic_challenge_consumption_under_concurrency() {
    use presentations::ReplayStore;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("private");
    drop(SqliteReplay::open(&root).unwrap());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut workers = vec![];
    for _ in 0..2 {
        let root = root.clone();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            let mut store = SqliteReplay::open(&root).unwrap();
            barrier.wait();
            store.consume(
                "verifier.example",
                "random-one-time-nonce",
                chrono::Utc::now().timestamp() + 300,
            )
        }));
    }
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_err_and(|e| e.code == "REPLAYED"))
            .count(),
        1
    );
}
