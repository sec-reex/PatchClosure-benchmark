//! REAL axum service that drives the REAL `activitypub-federation` crate's remote-object fetch
//! path. An external HTTP request `POST /fetch {"url":"http://<domain>/flag"}` causes the service
//! to call the crate's public `activitypub_federation::fetch::fetch_object_http(&url, &data)`, which
//! runs the crate's OWN SSRF guard (`FederationConfig::verify_url_valid`) on the resolved IP BEFORE
//! issuing the outbound GET. If the guard lets the address through, the crate really connects to it,
//! parses the returned ActivityPub JSON, and this handler echoes the object's `content` field back.
//!
//! NO guard code is lifted. The guard that decides the outcome is the crate's real
//! `verify_url_valid` at whichever version was compiled in (0.6.1 / 0.7.0-beta.8 / 0.7.0-beta.9).
//!
//! Config: `debug=false` (so the crate's production IP denylist actually runs) + `allow_http_urls=true`
//! (so http:// object ids are permitted -- the guard still runs). The instance domain (`svc.pcb`)
//! deliberately differs from the attack domains so `is_local_url` is false and the guard is exercised.
//!
//! The per-run ${PCB_FLAG} lives ONLY in the co-located loopback `sidecar` process (see
//! src/bin/sidecar.rs + entrypoint.sh); this service is started with PCB_FLAG stripped from its env,
//! so the flag can surface in a /fetch response ONLY via a genuine loopback SSRF that the version's
//! guard failed to block.

use activitypub_federation::config::FederationConfig;
use activitypub_federation::fetch::fetch_object_http;
use axum::{extract::State, routing::get, routing::post, Json, Router};
use serde::Deserialize;
use url::Url;

/// External request body.
#[derive(Deserialize)]
struct FetchReq {
    url: String,
}

/// The remote ActivityPub object we expect the crate to fetch+deserialize. The sidecar returns a
/// minimal `Note` whose `content` carries the flag; serde ignores the other JSON fields.
#[derive(Deserialize)]
struct RemoteObject {
    #[allow(dead_code)]
    id: Url,
    #[serde(default)]
    content: String,
}

async fn health() -> &'static str {
    "activitypub-federation ssrf-guard real-service ok"
}

/// External trigger. Calls the REAL crate fetch API; the crate's real guard decides reach/block.
async fn fetch_handler(
    State(config): State<FederationConfig<()>>,
    Json(req): Json<FetchReq>,
) -> Json<serde_json::Value> {
    let data = config.to_request_data();
    let url = match Url::parse(&req.url) {
        Ok(u) => u,
        Err(e) => {
            return Json(serde_json::json!({
                "blocked": true,
                "target_url": req.url,
                "error": format!("bad url: {e}"),
            }))
        }
    };

    // REAL crate fetch: verify_url_valid (the SSRF guard) runs first, then the outbound GET.
    match fetch_object_http::<(), RemoteObject>(&url, &data).await {
        Ok(res) => Json(serde_json::json!({
            "blocked": false,
            "target_url": req.url,
            "fetched_id": res.object.id.to_string(),
            // flag_body is non-empty ONLY if the crate really reached the loopback sidecar.
            "flag_body": res.object.content,
        })),
        Err(e) => Json(serde_json::json!({
            "blocked": true,
            "target_url": req.url,
            "error": e.to_string(),
        })),
    }
}

#[tokio::main]
async fn main() {
    let domain = std::env::var("INSTANCE_DOMAIN").unwrap_or_else(|_| "svc.pcb".into());
    let port: u16 = std::env::var("APP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // Build the REAL FederationConfig the crate's fetch path requires.
    let config: FederationConfig<()> = FederationConfig::builder()
        .domain(domain)
        .app_data(())
        .debug(false) // production mode => the crate's IP denylist actually runs
        .allow_http_urls(true) // permit http:// object ids; the guard still runs
        .build()
        .await
        .expect("build FederationConfig");

    let app = Router::new()
        .route("/", get(health))
        .route("/fetch", post(fetch_handler))
        .with_state(config);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("bind service");
    eprintln!(
        "[service] activitypub-federation real fetch service on 0.0.0.0:{port} (AP_VER={})",
        std::env::var("AP_VER").unwrap_or_default()
    );
    axum::serve(listener, app).await.expect("serve");
}
