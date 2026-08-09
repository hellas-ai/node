//! A quote must be answerable only for a model this node already holds,
//! and finding that out must cost nothing.
//!
//! The hole this closes: `quote_prepared_text` reaches
//! `program_manifest` with a caller-supplied model id, and resolving a
//! HuggingFace file path *is* downloading it. Any peer that could dial
//! the node could therefore name a 700 GB repository and have the node
//! fetch it, before any policy, payment or ticket.
//!
//! Asserting the error alone would not prove much: a refusal that
//! happens *after* a download attempt is still the hole. So this points
//! HuggingFace at a listener of our own and counts connections. Zero is
//! the claim.
//!
//! The counter is not taken on trust either — the second half of the
//! test runs the deliberate download path against the same listener and
//! requires it to connect. A counter that could never observe anything
//! would make the first assertion vacuous.

use std::io::Read as _;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hellas_models::{ModelAssetsError, Reach};
use hellas_rpc::Dtype;

/// A model no cache can hold: this repository does not exist, and the
/// revision is pinned, so nothing but a download could resolve it.
const MODEL: &str = "hellas-test/enormous-repository-of-the-attacker-s-choosing@\
                     c1899de289a04d12100db370d81485cdf75e47ca";

/// Accepts and immediately drops connections, counting them.
fn counting_endpoint() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("listener address").port();
    let connections = Arc::new(AtomicUsize::new(0));
    let observed = connections.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            observed.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut stream) = stream {
                // Read whatever the client sends, then hang up: we are
                // proving contact, not serving a repository.
                let _ = stream.read(&mut [0_u8; 512]);
                drop::<TcpStream>(stream);
            }
        }
    });
    (format!("http://127.0.0.1:{port}"), connections)
}

#[test]
fn a_quote_for_an_unmaterialized_model_is_refused_without_reaching_the_network() {
    let (endpoint, connections) = counting_endpoint();
    let cache = std::env::temp_dir().join(format!("hellas-quote-locality-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&cache);
    std::fs::create_dir_all(cache.join("hub")).expect("empty cache");

    // SAFETY: one test in its own binary; nothing else reads these.
    unsafe {
        std::env::set_var("HF_ENDPOINT", &endpoint);
        std::env::set_var("HF_HOME", &cache);
        // The gate also resolves against caches `hellas store adopt`
        // recorded. Point that registry at an empty directory: this test
        // is about a model nobody holds, and it must not depend on what
        // the developer running it happens to have adopted.
        std::env::set_var("HELLAS_STORE_DIR", cache.join("hellas"));
        std::env::remove_var("HF_TOKEN");
        std::env::remove_var("HUGGING_FACE_HUB_TOKEN");
    }

    // -- The quote path. Refused, and refused for the right reason.
    let err = hellas_models::program_manifest(MODEL, Dtype::F32, "cpu", Reach::Local)
        .expect_err("a model this node does not hold must not be quotable");
    match &err {
        ModelAssetsError::NotMaterialized {
            model_id, revision, ..
        } => {
            assert_eq!(
                model_id,
                "hellas-test/enormous-repository-of-the-attacker-s-choosing"
            );
            assert_eq!(revision, "c1899de289a04d12100db370d81485cdf75e47ca");
        }
        other => panic!("expected a not-materialized refusal, got {other:?}"),
    }
    // The refusal names what an operator would have to do about it.
    let message = err.to_string();
    assert!(
        message.contains("is not available on this node"),
        "{message}"
    );
    assert!(message.contains("--preload"), "{message}");

    // -- The claim: it cost nothing to find out.
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "the quote path opened a connection to HuggingFace",
    );

    // -- The control: the same listener does observe the deliberate
    //    path, so the zero above is a fact about the guard rather than
    //    about the counter.
    let _ = hellas_models::materialize_program_files(MODEL)
        .expect_err("the fake endpoint serves nothing, so this must fail");
    assert!(
        connections.load(Ordering::SeqCst) > 0,
        "the download path never contacted the endpoint, so the counter proves nothing",
    );

    let _ = std::fs::remove_dir_all(&cache);
}
