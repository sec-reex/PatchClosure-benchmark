//! Internal loopback SSRF canary sidecar (std-only, ZERO crate deps).
//!
//! Holds the per-run ${PCB_FLAG} and answers as a minimal ActivityPub object so that the crate's
//! REAL `fetch_object_http` will accept the response and hand the flag back to the service:
//!   - Content-Type: application/activity+json   (one of the crate's VALID_RESPONSE_CONTENT_TYPES)
//!   - body: {"@context":..,"id":"http://<Host><path>","type":"Note","content":"<PCB_FLAG>"}
//!     where `id` is reconstructed from the incoming Host header + path so it matches the crate's
//!     `extract_id(...) == res.url` check for ANY of the attack domains.
//!
//! It binds 0.0.0.0:80 IN THE SAME container as the service, so a connection to 127.0.0.1 (seed) or
//! to 0.0.0.0 (residual; the OS routes 0.0.0.0 -> localhost) reaches it. There is no host port: the
//! only way to read the flag is a server-side fetch from the service through the crate's guard.

use std::env;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn main() {
    let flag = env::var("PCB_FLAG").unwrap_or_default();
    let port: u16 = env::var("SIDE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80);
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind sidecar");
    eprintln!("[sidecar] 0.0.0.0:{port} serving PCB_FLAG as an activitypub object (internal, no host port)");
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let flag = flag.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);

            let mut path = "/".to_string();
            let mut host = "unknown".to_string();
            if let Some(first) = req.lines().next() {
                let mut it = first.split_whitespace();
                let _method = it.next();
                if let Some(p) = it.next() {
                    path = p.to_string();
                }
            }
            for line in req.lines() {
                let l = line.trim_start();
                if let Some(h) = l
                    .strip_prefix("Host:")
                    .or_else(|| l.strip_prefix("host:"))
                {
                    host = h.trim().to_string();
                }
            }

            let id = format!("http://{host}{path}");
            let body = format!(
                "{{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"{id}\",\"type\":\"Note\",\"content\":\"{flag}\"}}"
            );
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/activity+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        });
    }
}
