//! What a response is allowed to do to us.
//!
//! Every byte of a token, a reconstruction and a xorb range is read into
//! memory before anything about it is checked, and the length of each is
//! whatever the other end says it is. The whole-file hash at the end
//! catches wrong *content*; it catches nothing about a response that is
//! four gigabytes long, or a 200 with an entire xorb in it where a range
//! was asked for.
//!
//! None of that is reachable against production, which behaves. So this
//! file is a hub of our own: a listener that answers the three requests
//! `HfCas::fetch` makes, one badly at a time.
//!
//! The first test is the control. Without a happy path that works, every
//! refusal below could be a refusal of something else.

use std::io::{BufRead as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;

use hellas_store::hf::{FetchError, HfCas, Repo, RepoKind};
use hellas_xet::XetHash;

/// Any 64 hex digits: a xorb id is a key in the response, and nothing
/// checks it against the bytes.
const XORB: &str = "eea25d6ee393ccae385820daed127b96ef0ea034dfb7cf6da3a950ce334b7632";

/// How the fake hub should misbehave, if at all.
#[derive(Clone, Copy)]
enum Misbehaviour {
    None,
    /// A token response of a size nobody asked for.
    EnormousToken,
    /// The whole xorb in answer to a request for part of it.
    WholeXorbForARange,
    /// Exactly the bytes asked for, but a 200: "here is the whole
    /// thing", which for a xorb it is not.
    RightBytesWrongStatus,
    /// Fewer bytes than the range asked for, with the right status.
    ShortRange,
}

/// One framed chunk, stored uncompressed: an 8-byte header and the
/// bytes. Hand-rolled rather than imported, because the encoder lives in
/// the decoder's own test module and grading your own homework is what
/// that separation is for.
fn framed(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0_u8];
    out.extend_from_slice(&data.len().to_le_bytes()[..3]);
    out.push(0);
    out.extend_from_slice(&data.len().to_le_bytes()[..3]);
    out.extend_from_slice(data);
    out
}

/// Serves the three requests a fetch makes, and hangs up.
fn fake_hub(content: Arc<Vec<u8>>, how: Misbehaviour) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let base = format!("http://127.0.0.1:{port}");
    let hub = base.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
            let mut request = String::new();
            reader.read_line(&mut request).expect("request line");
            // Drain the headers so the client is not writing into a
            // socket nobody is reading.
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                    break;
                }
            }

            let xorb = framed(&content);
            let (status, body) = if request.contains("/xet-read-token/") {
                let token = match how {
                    Misbehaviour::EnormousToken => {
                        format!(
                            r#"{{"accessToken":"{}","casUrl":"{hub}"}}"#,
                            "a".repeat(70_000)
                        )
                    }
                    _ => format!(r#"{{"accessToken":"t","casUrl":"{hub}"}}"#),
                };
                (200, token.into_bytes())
            } else if request.contains("/v2/reconstructions/") {
                let last = xorb.len() - 1;
                (
                    200,
                    format!(
                        r#"{{"offset_into_first_range":0,
                            "terms":[{{"hash":"{XORB}","unpacked_length":{len},
                                       "range":{{"start":0,"end":1}}}}],
                            "xorbs":{{"{XORB}":[{{"url":"{hub}/xorb",
                                     "ranges":[{{"chunks":{{"start":0,"end":1}},
                                                 "bytes":{{"start":0,"end":{last}}}}}]}}]}}}}"#,
                        len = content.len(),
                    )
                    .into_bytes(),
                )
            } else {
                match how {
                    // A 200 means "here is the whole thing" — which for a
                    // xorb is every chunk of it, not the two that were
                    // asked for.
                    Misbehaviour::WholeXorbForARange => {
                        let mut whole = xorb.clone();
                        whole.extend_from_slice(&framed(b"another chunk entirely"));
                        (200, whole)
                    }
                    Misbehaviour::RightBytesWrongStatus => (200, xorb),
                    Misbehaviour::ShortRange => (206, xorb[..xorb.len() - 10].to_vec()),
                    _ => (206, xorb),
                }
            };

            let head = format!(
                "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });

    base
}

fn source(hub: &str) -> HfCas {
    HfCas::new(Repo {
        kind: RepoKind::Model,
        id: "hellas-test/fake".to_string(),
        revision: "main".to_string(),
    })
    .with_hub(hub)
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hellas-hub-responses-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn content() -> Arc<Vec<u8>> {
    Arc::new(
        (0..5_000_u32)
            .map(|index| (index * 31 % 251) as u8)
            .collect(),
    )
}

/// The control: three requests, one file, verified and published.
#[test]
fn a_well_behaved_hub_is_fetched_and_verified() {
    let content = content();
    let hub = fake_hub(content.clone(), Misbehaviour::None);
    let dir = scratch("happy");
    let dest = dir.join("model.safetensors");

    let written = source(&hub)
        .fetch(XetHash::hash(&content), &dest, None)
        .expect("a well-behaved hub");

    assert_eq!(written, content.len() as u64);
    assert_eq!(&std::fs::read(&dest).expect("read back"), content.as_ref());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A token is a small JSON object. A response that is not one must be
/// refused by its length, not accommodated.
#[test]
fn a_token_response_larger_than_a_token_is_refused() {
    let hub = fake_hub(content(), Misbehaviour::EnormousToken);
    match source(&hub).token() {
        Err(FetchError::TooLarge { limit, .. }) => assert_eq!(limit, 64 * 1024),
        other => panic!("expected a bounded read, got {other:?}"),
    }
}

/// A range request is the one case where the length is known before the
/// response arrives — so it is the one case where "however much you
/// send" is inexcusable. The read stops at what was asked for, which is
/// why this is refused as too large rather than as a wrong status: the
/// bound applies before anything is judged.
#[test]
fn a_range_answered_with_more_than_the_xorb_range_is_refused() {
    let content = content();
    let hub = fake_hub(content.clone(), Misbehaviour::WholeXorbForARange);
    let dir = scratch("whole-xorb");

    match source(&hub).fetch(XetHash::hash(&content), &dir.join("f.bin"), None) {
        Err(FetchError::TooLarge { limit, .. }) => {
            assert_eq!(
                limit,
                content.len() as u64 + 8,
                "the range that was asked for"
            );
        }
        other => panic!("expected the range to be refused, got {other:?}"),
    }
    assert!(!dir.join("f.bin").exists(), "nothing may be published");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The right number of bytes with the wrong status. A 200 says the URL
/// ignored the range and served the resource; that it happens to be the
/// same length is not something to rely on.
#[test]
fn a_range_answered_with_a_200_is_refused() {
    let content = content();
    let hub = fake_hub(content.clone(), Misbehaviour::RightBytesWrongStatus);
    let dir = scratch("wrong-status");

    match source(&hub).fetch(XetHash::hash(&content), &dir.join("f.bin"), None) {
        Err(FetchError::BadRange {
            status,
            expected,
            actual,
            ..
        }) => {
            assert_eq!(status, 200);
            assert_eq!(expected, actual, "the length was right; the status was not");
        }
        other => panic!("expected the status to be refused, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other direction: a 206 that is short. The status was right and
/// the byte count was not.
#[test]
fn a_range_shorter_than_it_should_be_is_refused() {
    let content = content();
    let hub = fake_hub(content.clone(), Misbehaviour::ShortRange);
    let dir = scratch("short");

    match source(&hub).fetch(XetHash::hash(&content), &dir.join("f.bin"), None) {
        Err(FetchError::BadRange {
            status,
            expected,
            actual,
            ..
        }) => {
            assert_eq!(status, 206);
            assert_eq!(expected - actual, 10);
        }
        other => panic!("expected the short range to be refused, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A range that ends before it starts underflows at `end - start` and
/// becomes an enormous number several layers below the parse. It is
/// refused at the parse instead.
#[test]
fn a_range_that_ends_before_it_starts_does_not_parse() {
    use hellas_store::hf::Reconstruction;

    let backwards_chunks = format!(
        r#"{{"terms":[{{"hash":"{XORB}","unpacked_length":1,"range":{{"start":9,"end":2}}}}],
            "xorbs":{{}}}}"#
    );
    assert!(matches!(
        Reconstruction::parse(&backwards_chunks),
        Err(FetchError::Malformed(_)),
    ));

    let backwards_bytes = format!(
        r#"{{"terms":[],
            "xorbs":{{"{XORB}":[{{"url":"http://example.invalid",
              "ranges":[{{"chunks":{{"start":0,"end":1}},
                          "bytes":{{"start":100,"end":0}}}}]}}]}}}}"#
    );
    assert!(matches!(
        Reconstruction::parse(&backwards_bytes),
        Err(FetchError::Malformed(_)),
    ));

    // The control: the same shapes, the right way round.
    let forwards = format!(
        r#"{{"terms":[{{"hash":"{XORB}","unpacked_length":1,"range":{{"start":2,"end":9}}}}],
            "xorbs":{{"{XORB}":[{{"url":"http://example.invalid",
              "ranges":[{{"chunks":{{"start":0,"end":1}},
                          "bytes":{{"start":0,"end":100}}}}]}}]}}}}"#
    );
    assert!(Reconstruction::parse(&forwards).is_ok());
}
