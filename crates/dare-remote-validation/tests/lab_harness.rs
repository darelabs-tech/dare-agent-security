//! The REMOTE-LAB harness itself works, and leaves no key behind.

mod lab;

use std::sync::Arc;

use lab::{always, LabCa, LabReply, LabServer};

fn client(ca: &LabCa) -> reqwest::Client {
    reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_der(&ca.root).expect("root")])
        .no_proxy()
        .build()
        .expect("client")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lab_server_answers_over_tls_trusted_only_through_the_lab_root() {
    let ca = LabCa::generate();
    let server = LabServer::start(
        &ca,
        always(LabReply::json(200, serde_json::json!({"ok": true}))),
    )
    .await;
    let response = client(&ca)
        .get(format!("{}/probe", server.origin))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 200);
    let hits = server.hits();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].path, "/probe");
    assert!(hits[0].peer.ip().is_loopback());

    // A client that trusts a different lab CA refuses the connection.
    let other = LabCa::generate();
    assert!(client(&other)
        .get(format!("{}/probe", server.origin))
        .send()
        .await
        .is_err());
    assert_eq!(server.hits().len(), 1, "no request reached the handler");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_for_another_name_fails_verification() {
    let ca = LabCa::generate();
    let server =
        LabServer::start_with_names(&ca, &["wrong.example.test"], always(LabReply::status(200)))
            .await;
    let error = client(&ca)
        .get(format!("{}/", server.origin))
        .send()
        .await
        .expect_err("name mismatch");
    assert!(error.is_connect() || error.is_request(), "{error}");
    assert!(server.hits().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn handlers_see_the_request_and_can_keep_state() {
    let ca = LabCa::generate();
    let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let seen = count.clone();
    let handler: lab::Handler = Arc::new(move |hit| {
        let n = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        LabReply::json(200, serde_json::json!({"n": n, "len": hit.body.len()}))
    });
    let server = LabServer::start(&ca, handler).await;
    for expected in 0..3u32 {
        let reply: serde_json::Value = client(&ca)
            .post(format!("{}/t", server.origin))
            .body("abc")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(reply["n"], expected);
        assert_eq!(reply["len"], 3);
    }
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[test]
fn no_private_key_is_checked_in_anywhere_in_this_crate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            assert!(
                !matches!(ext, "pem" | "key" | "der" | "p12" | "pfx" | "crt"),
                "{} looks like key material",
                path.display()
            );
            if let Ok(text) = std::fs::read_to_string(&path) {
                assert!(
                    !text.contains(&["-----BEGIN", " PRIVATE KEY-----"].concat()),
                    "{}",
                    path.display()
                );
            }
        }
    }
}
