use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use crate::http_get_auth as auth;
use hyper::{Method, Request, Response, StatusCode, service::service_fn};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc};

const MAX_SESSIONS: usize = 128;
const MAX_UPLOAD: usize = 4096;
const MAX_DATAGRAM: usize = 2048;
const MAX_DOWNLOAD: usize = 65536;
const QUEUE_CAPACITY: usize = 256;
const IDLE: u64 = 60;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    http_get: Settings,
}

#[derive(Deserialize)]
struct Settings {
    version: u32,
    #[serde(default = "get_method")]
    method: String,
    port: u16,
    path: String,
    credentials: HashSet<String>,
    restricted: bool,
    destinations: Vec<Destination>,
}

fn get_method() -> String { "GET".to_string() }

#[derive(Deserialize)]
struct Destination {
    host: String,
    port: u16,
}

struct State {
    settings: Settings,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    auth: auth::Guard,
}

struct Session {
    socket: Arc<UdpSocket>,
    destination: String,
    last: AtomicU64,
    failed: AtomicBool,
    dropped_packets: AtomicU64,
    dropped_bytes: AtomicU64,
    upload: Mutex<u64>,
    download: Mutex<Download>,
}

struct Download {
    receiver: mpsc::Receiver<Vec<u8>>,
    sequence: u64,
    pending: Vec<u8>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn concealed() -> Response<Full<Bytes>> {
    Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::new())).unwrap()
}

fn reply(status: StatusCode, data: Vec<u8>, sequence: u64) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Cache-Control", "no-store, private")
        .header("X-Accel-Buffering", "no")
        .header("Content-Type", "application/octet-stream")
        .header("X-WG-Version", auth::VERSION)
        .header("X-WG-Seq", sequence.to_string())
        .body(Full::new(Bytes::from(data)))
        .unwrap()
}

fn session_reply(session: &Session, status: StatusCode, data: Vec<u8>, sequence: u64) -> Response<Full<Bytes>> {
    let mut response = reply(status, data, sequence);
    response.headers_mut().insert("x-wg-down-dropped", session.dropped_packets.load(Ordering::Relaxed).to_string().parse().unwrap());
    response
}

fn frames(data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if data.len() - offset < 2 { return None; }
        let size = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        if size == 0 || size > MAX_DATAGRAM || size > data.len() - offset { return None; }
        result.push(&data[offset..offset + size]);
        offset += size;
    }
    if result.is_empty() { None } else { Some(result) }
}

fn frame(data: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(&(data.len() as u16).to_be_bytes());
    output.extend_from_slice(data);
}

async fn create_session(host: &str, port: u16) -> anyhow::Result<Arc<Session>> {
    let destination = format!("{}:{}", host.trim_end_matches('.').to_lowercase(), port);
    let address = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((host, port)))
        .await?.context("target resolution failed")?.next().context("target has no address")?;
    let socket = Arc::new(UdpSocket::bind(if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?);
    socket.connect(address).await?;
    let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
    let session = Arc::new(Session {
        socket: socket.clone(), destination, last: AtomicU64::new(now()), failed: AtomicBool::new(false),
        dropped_packets: AtomicU64::new(0), dropped_bytes: AtomicU64::new(0),
        upload: Mutex::new(0), download: Mutex::new(Download { receiver, sequence: 0, pending: Vec::new() }),
    });
    let weak = Arc::downgrade(&session);
    tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        let mut pending_drops = 0u64;
        let mut pending_bytes = 0u64;
        let mut next_report = std::time::Instant::now();
        loop {
            let Some(current) = weak.upgrade() else { return; };
            if current.failed.load(Ordering::Acquire) || now().saturating_sub(current.last.load(Ordering::Relaxed)) > IDLE { return; }
            drop(current);
            match tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buffer)).await {
                Err(_) => continue,
                Ok(Err(_)) => {
                    if let Some(current) = weak.upgrade() { current.failed.store(true, Ordering::Release); }
                    return;
                }
                Ok(Ok(count)) => {
                    if count == 0 || count > MAX_DATAGRAM {
                        if let Some(current) = weak.upgrade() { current.failed.store(true, Ordering::Release); }
                        tracing::warn!("HTTP GET UDP datagram limit exceeded");
                        return;
                    }
                    match sender.try_send(buffer[..count].to_vec()) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            let Some(current) = weak.upgrade() else { return; };
                            let total_packets = current.dropped_packets.fetch_add(1, Ordering::Relaxed) + 1;
                            let total_bytes = current.dropped_bytes.fetch_add(count as u64, Ordering::Relaxed) + count as u64;
                            pending_drops += 1;
                            pending_bytes += count as u64;
                            if std::time::Instant::now() >= next_report {
                                let event = serde_json::json!({"v": 1, "stage": "hub", "droppedPackets": pending_drops,
                                    "droppedBytes": pending_bytes, "totalPackets": total_packets, "totalBytes": total_bytes,
                                    "capacityBytes": 0, "capacityPackets": QUEUE_CAPACITY});
                                tracing::warn!("AG_UDP_PRESSURE {}", event);
                                pending_drops = 0;
                                pending_bytes = 0;
                                next_report = std::time::Instant::now() + Duration::from_secs(10);
                            }
                        }
                    }
                }
            }
        }
    });
    Ok(session)
}

fn probe_nonce(path: &str, prefix: &str) -> Option<String> {
    let nonce = path.strip_prefix(&format!("{prefix}_amneziageo/probe/"))?;
    (nonce.len() == 32 && nonce.bytes().all(|value| value.is_ascii_hexdigit())).then(|| nonce.to_string())
}

fn allowed(settings: &Settings, host: &str, port: u16) -> bool {
    !settings.restricted || settings.destinations.iter().any(|value| value.port == port
        && value.host.trim_end_matches('.').eq_ignore_ascii_case(host.trim_end_matches('.')))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && host.bytes().all(|value| value.is_ascii_alphanumeric() || b".-:".contains(&value))
}

async fn signed(response: Response<Full<Bytes>>, verified: &auth::Verified, guard: &auth::Guard) -> Response<Full<Bytes>> {
    let (mut parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let time = guard.time();
    parts.headers.insert("x-wg-epoch", auth::hex(&guard.epoch).parse().unwrap());
    parts.headers.insert("x-wg-time", time.to_string().parse().unwrap());
    let signature = verified.keys.response(&verified.request, auth::Response {
        status: parts.status, epoch: &guard.epoch, time, version: auth::VERSION,
        sequence: auth::one(&parts.headers,"x-wg-seq").unwrap_or(""),
        dropped: auth::one(&parts.headers,"x-wg-down-dropped").unwrap_or(""),
        fault: auth::one(&parts.headers,"x-wg-auth-error").unwrap_or(""), body: &body,
    });
    parts.headers.insert("x-wg-auth",signature.parse().unwrap());
    Response::from_parts(parts, Full::new(body))
}

async fn handle<B>(request: Request<B>, state: Arc<State>) -> Result<Response<Full<Bytes>>, std::convert::Infallible>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let empty = || Ok(concealed());
    if request.method().as_str() != state.settings.method { return empty(); }
    if request.headers().contains_key("upgrade")
        || (request.method() == Method::GET && (request.headers().contains_key("transfer-encoding")
            || request.headers().get("content-length").is_some_and(|value| value.as_bytes() != b"0")))
        || (request.method() == Method::POST && request.headers().contains_key("x-wg-data")) {
        return empty();
    }
    let (parts, body) = request.into_parts();
    let payload = if parts.method == Method::POST {
        match tokio::time::timeout(Duration::from_secs(5), Limited::new(body, MAX_UPLOAD).collect()).await {
            Ok(Ok(body)) => body.to_bytes().to_vec(),
            Ok(Err(_)) => return empty(),
            Err(_) => return empty(),
        }
    } else if parts.headers.contains_key("x-wg-data") {
        let Some(encoded) = auth::one(&parts.headers,"x-wg-data").filter(|value| value.len() <= 5464) else { return empty(); };
        let Ok(value) = STANDARD.decode(encoded) else { return empty(); };
        if value.len() > MAX_UPLOAD || STANDARD.encode(&value) != encoded { return empty(); }
        value
    } else { Vec::new() };
    let request = Request::from_parts(parts, ());
    let probe = probe_nonce(request.uri().path(), &state.settings.path);
    if request.uri().path() != state.settings.path && probe.is_none() { return empty(); }
    let Some(query) = auth::query(request.uri().query().unwrap_or("")) else { return empty(); };
    if request.uri().path() == state.settings.path && query.get("op").is_some_and(|value| value == "challenge") {
        if query.len() != 2 || !payload.is_empty() || request.headers().contains_key("x-wg-data") { return empty(); }
        let Some(nonce) = query.get("n") else { return empty(); };
        let Some((body,proof)) = state.auth.challenge(request.headers(),request.uri().path(),nonce) else { return empty(); };
        let mut response = reply(StatusCode::OK, body, 0);
        response.headers_mut().insert("x-wg-auth",proof.parse().unwrap());
        response.headers_mut().insert("content-type","application/json".parse().unwrap());
        return Ok(response);
    }
    let verified = match state.auth.authorize(request.headers(),request.method().as_str(),request.uri().path(),&query,&payload) {
        Ok(verified) => verified,
        Err(failure) => {
            let Some(verified) = failure.verified else { return empty(); };
            let mut response = reply(failure.status, Vec::new(), 0);
            if !failure.fault.is_empty() { response.headers_mut().insert("x-wg-auth-error",failure.fault.parse().unwrap()); }
            return Ok(signed(response,&verified,&state.auth).await);
        }
    };
    let response = dispatch(request,state.clone(),&verified.keys.identity,query,probe,payload).await?;
    Ok(signed(response,&verified,&state.auth).await)
}

async fn dispatch(_request: Request<()>, state: Arc<State>, identity: &str, query: std::collections::BTreeMap<String,String>, probe: Option<String>, payload: Vec<u8>) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let empty = |status| Ok(reply(status, Vec::new(), 0));
    if let Some(nonce) = probe {
        let destination = if query.contains_key("host") || query.contains_key("port") {
            let Some(host) = query.get("host").filter(|host| valid_host(host)) else { return empty(StatusCode::BAD_REQUEST); };
            let Some(port) = query.get("port").and_then(|port| port.parse::<u16>().ok()).filter(|port| *port > 0) else { return empty(StatusCode::BAD_REQUEST); };
            if !allowed(&state.settings,host,port) {
                return Ok(reply(StatusCode::FORBIDDEN,serde_json::to_vec(&serde_json::json!({"error":"proxy-target-denied"})).unwrap(),0));
            }
            Some(serde_json::json!({"host":host.trim_end_matches('.').to_lowercase(),"port":port}))
        } else { None };
        let mut body = serde_json::json!({"nonce":nonce,"transport":"xhttp","running":true});
        if let Some(destination) = destination { body["target"] = destination; body["allowed"] = true.into(); }
        let mut response = reply(StatusCode::OK,serde_json::to_vec(&body).unwrap(),0);
        response.headers_mut().insert("content-type","application/json".parse().unwrap());
        return Ok(response);
    }
    let Some(id) = query.get("s").filter(|id| id.len() == 32 && id.bytes().all(|value| value.is_ascii_hexdigit())) else { return empty(StatusCode::BAD_REQUEST); };
    let key = format!("{identity}/{id}");
    let operation = query.get("op").map(String::as_str).unwrap_or("");
    if operation == "open" {
        let Some(host) = query.get("host").filter(|s| !s.is_empty() && s.len() <= 253
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b))) else {
            return empty(StatusCode::BAD_REQUEST);
        };
        let Some(port) = query.get("port").and_then(|s| s.parse::<u16>().ok()).filter(|p| *p > 0) else {
            return empty(StatusCode::BAD_REQUEST);
        };
        if state.settings.restricted && !state.settings.destinations.iter().any(|d| d.port == port
            && d.host.trim_end_matches('.').eq_ignore_ascii_case(host.trim_end_matches('.'))) {
            return empty(StatusCode::FORBIDDEN);
        }
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.get(&key) {
            if session.destination != format!("{}:{}", host.trim_end_matches('.').to_lowercase(), port) {
                return empty(StatusCode::CONFLICT);
            }
            session.last.store(now(), Ordering::Relaxed);
            return empty(StatusCode::OK);
        }
        if sessions.len() >= MAX_SESSIONS { return empty(StatusCode::TOO_MANY_REQUESTS); }
        match create_session(host, port).await {
            Ok(session) => { sessions.insert(key, session); return empty(StatusCode::OK); }
            Err(error) => {
                tracing::warn!(error = %error, "HTTP GET UDP session did not open");
                return empty(StatusCode::BAD_GATEWAY);
            }
        }
    }
    let session = {
        let mut sessions = state.sessions.lock().await;
        if operation == "close" { sessions.remove(&key); return empty(StatusCode::OK); }
        sessions.get(&key).cloned()
    };
    let Some(session) = session else { return empty(StatusCode::GONE); };
    session.last.store(now(), Ordering::Relaxed);
    if session.failed.load(Ordering::Acquire) { return empty(StatusCode::SERVICE_UNAVAILABLE); }
    if operation == "push" {
        let Some(number) = query.get("seq").and_then(|s| s.parse::<u64>().ok()).filter(|n| *n > 0) else {
            return empty(StatusCode::BAD_REQUEST);
        };
        let data = payload;
        let Some(packets) = frames(&data) else { return empty(StatusCode::BAD_REQUEST); };
        let mut previous = session.upload.lock().await;
        if number <= *previous { return Ok(session_reply(&session, StatusCode::OK, Vec::new(), *previous)); }
        if number != *previous + 1 { return Ok(session_reply(&session, StatusCode::CONFLICT, Vec::new(), *previous)); }
        *previous = number;
        for packet in packets {
            if session.socket.send(packet).await.is_err() {
                session.failed.store(true, Ordering::Release);
                return empty(StatusCode::BAD_GATEWAY);
            }
        }
        return Ok(session_reply(&session, StatusCode::OK, Vec::new(), number));
    }
    if operation == "pull" {
        let Some(ack) = query.get("ack").and_then(|s| s.parse::<u64>().ok()) else {
            return empty(StatusCode::BAD_REQUEST);
        };
        let mut download = session.download.lock().await;
        if ack > download.sequence { return empty(StatusCode::CONFLICT); }
        if !download.pending.is_empty() {
            if ack < download.sequence { return Ok(session_reply(&session, StatusCode::OK, download.pending.clone(), download.sequence)); }
            download.pending.clear();
        } else if ack != download.sequence { return empty(StatusCode::CONFLICT); }
        let first = match tokio::time::timeout(Duration::from_secs(5), download.receiver.recv()).await {
            Err(_) => return Ok(session_reply(&session, StatusCode::NO_CONTENT, Vec::new(), download.sequence)),
            Ok(None) => return empty(StatusCode::SERVICE_UNAVAILABLE),
            Ok(Some(packet)) => packet,
        };
        frame(&first, &mut download.pending);
        while download.pending.len() + MAX_DATAGRAM + 2 <= MAX_DOWNLOAD {
            match download.receiver.try_recv() {
                Ok(packet) => frame(&packet, &mut download.pending),
                Err(_) => break,
            }
        }
        download.sequence += 1;
        return Ok(session_reply(&session, StatusCode::OK, download.pending.clone(), download.sequence));
    }
    empty(StatusCode::BAD_REQUEST)
}

pub async fn serve(file: &std::path::Path) -> anyhow::Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(file)?)?;
    let settings = config.http_get;
    if settings.version != 2 || !matches!(settings.method.as_str(), "GET" | "POST") || settings.port == 0 || settings.credentials.is_empty()
        || !settings.path.starts_with('/') || !settings.path.ends_with('/') { bail!("invalid HTTP GET profile"); }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, settings.port)).await?;
    let auth = auth::Guard::new(&settings.credentials)?;
    let state = Arc::new(State { settings, sessions: Mutex::new(HashMap::new()), auth });
    let weak = Arc::downgrade(&state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let Some(state) = weak.upgrade() else { return; };
            state.sessions.lock().await.retain(|_, s| now().saturating_sub(s.last.load(Ordering::Relaxed)) <= IDLE);
        }
    });
    tracing::info!("HTTP GET UDP server version 2 started");
    let connections = Arc::new(tokio::sync::Semaphore::new(256));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else { continue; };
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request| handle(request, state.clone()));
            if let Err(error) = hyper::server::conn::http1::Builder::new().max_buf_size(16384)
                .serve_connection(TokioIo::new(stream), service).await {
                tracing::debug!(error = %error, "HTTP GET connection ended");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderName;
    use ring::{hkdf, hmac};
    use hyper::body::Body;

    const CREDENTIAL: &str = "40168f45-37b1-4bfa-903c-9904f48489ae";
    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    fn state(method: &str, destinations: Vec<Destination>) -> Arc<State> {
        let credentials = HashSet::from([CREDENTIAL.to_string()]);
        Arc::new(State {
            settings: Settings {
                version: 2, method: method.to_string(), port: 1, path: "/native/".to_string(),
                credentials: credentials.clone(), restricted: true, destinations,
            },
            sessions: Mutex::new(HashMap::new()),
            auth: auth::Guard::new(&credentials).unwrap(),
        })
    }

    fn field(data: &mut Vec<u8>, value: &[u8]) {
        data.extend_from_slice(&(value.len() as u32).to_be_bytes());
        data.extend_from_slice(value);
    }

    fn mac(purpose: &[u8], message: &[u8]) -> String {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"amneziageo.http-get.v2");
        let root = salt.extract(CREDENTIAL.as_bytes());
        let info = [purpose];
        let material = root.expand(&info, hkdf::HKDF_SHA256).unwrap();
        let mut key = [0; 32];
        material.fill(&mut key).unwrap();
        STANDARD.encode(hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), message).as_ref())
    }

    fn signed_request(state: &State, path: &str, query: &str, payload: &[u8], nonce: u8) -> (Request<Full<Bytes>>, [u8; 32]) {
        let method = &state.settings.method;
        let keys = auth::Keys::derive(CREDENTIAL).unwrap();
        let query_fields = auth::query(query).unwrap();
        let time = state.auth.time();
        let mut message = Vec::new();
        for value in [b"amneziageo.http-get.request.v2".as_slice(), method.as_bytes(), path.as_bytes(), &keys.id, &state.auth.epoch] {
            field(&mut message, value);
        }
        message.extend_from_slice(&time.to_be_bytes());
        field(&mut message, &[nonce; 16]);
        message.extend_from_slice(&(query_fields.len() as u16).to_be_bytes());
        for (name, value) in query_fields {
            field(&mut message, name.as_bytes());
            field(&mut message, value.as_bytes());
        }
        field(&mut message, &auth::hash(payload));
        let mut builder = Request::builder().method(method.as_str()).uri(format!("{path}?{query}"))
            .header("x-wg-version", auth::VERSION).header("x-wg-key", &keys.identity)
            .header("x-wg-epoch", auth::hex(&state.auth.epoch)).header("x-wg-time", time.to_string())
            .header("x-wg-nonce", auth::hex(&[nonce; 16])).header("x-wg-auth", mac(b"request", &message));
        let body = if method == "POST" {
            payload.to_vec()
        } else {
            if !payload.is_empty() { builder = builder.header("x-wg-data", STANDARD.encode(payload)); }
            Vec::new()
        };
        (builder.body(Full::new(Bytes::from(body))).unwrap(), auth::hash(&message))
    }

    async fn hidden(response: Response<Full<Bytes>>) {
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(response.headers().is_empty(), "{:?}", response.headers());
        assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
    }

    async fn authenticated(response: Response<Full<Bytes>>, hash: &[u8; 32], status: StatusCode) -> (hyper::HeaderMap, Bytes) {
        let (parts, body) = response.into_parts();
        assert_eq!(parts.status, status);
        let body = body.collect().await.unwrap().to_bytes();
        assert_eq!(auth::one(&parts.headers, "x-wg-version"), Some(auth::VERSION));
        let keys = auth::Keys::derive(CREDENTIAL).unwrap();
        let epoch = auth::one(&parts.headers, "x-wg-epoch").and_then(auth::unhex::<16>).unwrap();
        let time = auth::one(&parts.headers, "x-wg-time").unwrap().parse().unwrap();
        let expected = keys.response(hash, auth::Response {
            status, epoch: &epoch, time, version: auth::VERSION,
            sequence: auth::one(&parts.headers, "x-wg-seq").unwrap(),
            dropped: auth::one(&parts.headers, "x-wg-down-dropped").unwrap_or(""),
            fault: auth::one(&parts.headers, "x-wg-auth-error").unwrap_or(""), body: &body,
        });
        assert_eq!(auth::one(&parts.headers, "x-wg-auth"), Some(expected.as_str()));
        (parts.headers, body)
    }

    #[test]
    fn frames_keep_datagram_boundaries() {
        let mut data = Vec::new();
        frame(&[1, 2, 3], &mut data);
        frame(&[4, 5], &mut data);
        assert_eq!(frames(&data).unwrap(), vec![&[1, 2, 3][..], &[4, 5][..]]);
        assert!(frames(&data[..data.len() - 1]).is_none());
        assert!(frames(&[0, 0]).is_none());
        assert!(frames(&[]).is_none());
    }

    #[tokio::test]
    async fn anonymous_failures_match_unknown_path() {
        let state = state("GET", Vec::new());
        let cases = [
            ("GET", "/missing/", vec![]),
            ("GET", "/native/?op=challenge", vec![]),
            ("GET", "/native/?op=unknown", vec![]),
            ("GET", "/native/?op=open&op=pull", vec![]),
            ("GET", "/native/?op=%zz", vec![]),
            ("GET", "/native/?op=open", vec![("x-wg-version", "1")]),
            ("GET", "/native/?op=open", vec![("x-wg-version", "2"), ("x-wg-key", "unknown")]),
            ("GET", "/native/?op=open", vec![("upgrade", "websocket")]),
            ("GET", "/native/?op=push", vec![("content-length", "1")]),
            ("GET", "/native/?op=push", vec![("transfer-encoding", "chunked")]),
            ("GET", "/native/?op=push", vec![("x-wg-data", "?")]),
            ("POST", "/native/?op=challenge", vec![]),
            ("PUT", "/native/?op=open", vec![]),
            ("HEAD", "/native/", vec![]),
            ("OPTIONS", "/native/", vec![]),
        ];
        for (method, uri, headers) in cases {
            let mut request = Request::builder().method(method).uri(uri);
            for (name, value) in headers { request = request.header(name, value); }
            hidden(handle(request.body(Full::new(Bytes::new())).unwrap(), state.clone()).await.unwrap()).await;
        }
        let (mut bad_mac, _) = signed_request(&state, "/native/", "op=open", &[], 1);
        bad_mac.headers_mut().insert("x-wg-auth", STANDARD.encode([0; 32]).parse().unwrap());
        hidden(handle(bad_mac, state.clone()).await.unwrap()).await;
        let (mut bad_version, _) = signed_request(&state, "/native/", "op=open", &[], 2);
        bad_version.headers_mut().insert("x-wg-version", "3".parse().unwrap());
        hidden(handle(bad_version, state.clone()).await.unwrap()).await;
        let (mut duplicate, _) = signed_request(&state, "/native/", "op=open", &[], 3);
        duplicate.headers_mut().append(HeaderName::from_static("x-wg-key"), "duplicate".parse().unwrap());
        hidden(handle(duplicate, state.clone()).await.unwrap()).await;
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn anonymous_wire_profiles_keep_the_connection_and_match_unknown_path() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpStream;

        for method in ["GET", "POST"] {
            let state = state(method, Vec::new());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(move |request| handle(request, state.clone())))
                    .await.unwrap();
            });
            let mut client = BufReader::new(TcpStream::connect(address).await.unwrap());
            let mut baseline = None;
            for (path, headers) in [
                ("/missing/", ""),
                ("/native/?op=challenge", ""),
                ("/native/?op=unknown", ""),
                ("/native/?op=open", "X-WG-Version: 1\r\n"),
                ("/native/?op=open", "X-WG-Version: 2\r\nX-WG-Key: unknown\r\n"),
            ] {
                let message = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n{headers}\r\n");
                client.get_mut().write_all(message.as_bytes()).await.unwrap();
                let profile = tokio::time::timeout(Duration::from_secs(3), async {
                    let mut profile = Vec::new();
                    loop {
                        let mut line = String::new();
                        assert!(client.read_line(&mut line).await.unwrap() > 0);
                        if line == "\r\n" { return profile; }
                        let line = line.trim_end().to_lowercase();
                        if !line.starts_with("date:") { profile.push(line); }
                    }
                }).await.unwrap();
                assert_eq!(profile[0], "http/1.1 404 not found");
                assert!(profile.contains(&"content-length: 0".to_string()));
                assert!(!profile.iter().any(|line| line.starts_with("x-wg-") || line.starts_with("content-type:")
                    || line.starts_with("cache-control:") || line.starts_with("x-accel-buffering:")));
                if let Some(baseline) = &baseline { assert_eq!(&profile, baseline); } else { baseline = Some(profile); }
            }
            drop(client);
            tokio::time::timeout(Duration::from_secs(3), server).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn post_failures_and_body_limit_match_unknown_path() {
        let state = state("POST", Vec::new());
        for uri in ["/native/?op=open", "/missing/?op=open"] {
            for body in [Vec::new(), vec![42; MAX_UPLOAD + 1]] {
                let request = Request::builder().method("POST").uri(uri).body(Full::new(Bytes::from(body))).unwrap();
                hidden(handle(request, state.clone()).await.unwrap()).await;
            }
        }
        let request = Request::builder().method("POST").uri("/native/?op=push").header("x-wg-data", "AA==")
            .body(Full::new(Bytes::new())).unwrap();
        hidden(handle(request, state.clone()).await.unwrap()).await;
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn post_body_timeout_matches_unknown_path() {
        let state = state("POST", Vec::new());
        let timeout_case = |path: &'static str, state: Arc<State>| async move {
            let stream = futures_util::stream::pending::<Result<hyper::body::Frame<Bytes>, std::convert::Infallible>>();
            let request = Request::builder().method("POST").uri(path).body(http_body_util::StreamBody::new(stream)).unwrap();
            hidden(handle(request, state).await.unwrap()).await;
        };
        tokio::time::timeout(Duration::from_secs(8), async {
            tokio::join!(timeout_case("/native/?op=open", state.clone()), timeout_case("/missing/", state));
        }).await.unwrap();
    }

    #[tokio::test]
    async fn legacy_v2_challenge_keeps_server_proof_for_known_identity() {
        for method in ["GET", "POST"] {
            let state = state(method, Vec::new());
            let keys = auth::Keys::derive(CREDENTIAL).unwrap();
            let nonce = [4; 16];
            let uri = format!("/native/?op=challenge&n={}", auth::hex(&nonce));
            let request = Request::builder().method(method).uri(&uri).header("x-wg-version", "2")
                .header("x-wg-key", &keys.identity).body(Full::new(Bytes::new())).unwrap();
            let response = handle(request, state.clone()).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let (parts, body) = response.into_parts();
            let value: serde_json::Value = serde_json::from_slice(&body.collect().await.unwrap().to_bytes()).unwrap();
            assert_eq!(value["epoch"].as_str(), Some(auth::hex(&state.auth.epoch).as_str()));
            let proof = keys.challenge("/native/", &nonce, &state.auth.epoch, value["time"].as_u64().unwrap());
            assert_eq!(auth::one(&parts.headers, "x-wg-auth"), Some(proof.as_str()));
            assert_eq!(auth::one(&parts.headers, "x-wg-version"), Some("2"));
            let request = Request::builder().method(method).uri(uri).header("x-wg-version", "2")
                .header("x-wg-key", auth::hex(&[0; 32])).body(Full::new(Bytes::new())).unwrap();
            hidden(handle(request, state.clone()).await.unwrap()).await;
            assert!(state.sessions.lock().await.is_empty());
        }
    }

    #[tokio::test]
    async fn signed_target_errors_and_replays_keep_authenticated_diagnostics() {
        let state = state("GET", vec![Destination { host: "127.0.0.1".to_string(), port: 12345 }]);
        let query = format!("op=open&s={SESSION}&host=127.0.0.1&port=12346");
        let (request, hash) = signed_request(&state, "/native/", &query, &[], 5);
        let replay = request.clone();
        authenticated(handle(request, state.clone()).await.unwrap(), &hash, StatusCode::FORBIDDEN).await;
        let (headers, _) = authenticated(handle(replay, state.clone()).await.unwrap(), &hash, StatusCode::CONFLICT).await;
        assert_eq!(auth::one(&headers, "x-wg-auth-error"), Some("replay"));
        let probe = "/native/_amneziageo/probe/0123456789abcdef0123456789abcdef";
        let (request, hash) = signed_request(&state, probe, "host=127.0.0.1&port=12346", &[], 6);
        let (_, body) = authenticated(handle(request, state.clone()).await.unwrap(), &hash, StatusCode::FORBIDDEN).await;
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"], "proxy-target-denied");
        let (mut tampered, _) = signed_request(&state, "/native/", &query, &[], 7);
        *tampered.uri_mut() = format!("/native/?op=open&s={SESSION}&host=127.0.0.1&port=12345").parse().unwrap();
        hidden(handle(tampered, state.clone()).await.unwrap()).await;
        assert!(state.sessions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn authorized_get_and_post_preserve_datagrams() {
        for method in ["GET", "POST"] {
            let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = echo.local_addr().unwrap().port();
            let worker = tokio::spawn(async move {
                let mut data = [0; MAX_DATAGRAM];
                let (size, peer) = echo.recv_from(&mut data).await.unwrap();
                echo.send_to(&data[..size], peer).await.unwrap();
            });
            let state = state(method, vec![Destination { host: "127.0.0.1".to_string(), port }]);
            let query = format!("op=open&s={SESSION}&host=127.0.0.1&port={port}");
            let (request, hash) = signed_request(&state, "/native/", &query, &[], 8);
            authenticated(handle(request, state.clone()).await.unwrap(), &hash, StatusCode::OK).await;
            let mut payload = Vec::new();
            frame(b"datagram body", &mut payload);
            let (request, hash) = signed_request(&state, "/native/", &format!("op=push&s={SESSION}&seq=1"), &payload, 9);
            if method == "GET" {
                assert!(request.body().size_hint().exact() == Some(0));
                assert!(request.headers().contains_key("x-wg-data"));
            } else {
                assert!(request.body().size_hint().exact() == Some(payload.len() as u64));
                assert!(!request.headers().contains_key("x-wg-data"));
            }
            authenticated(handle(request, state.clone()).await.unwrap(), &hash, StatusCode::OK).await;
            let (request, hash) = signed_request(&state, "/native/", &format!("op=pull&s={SESSION}&ack=0"), &[], 10);
            let (_, body) = authenticated(handle(request, state.clone()).await.unwrap(), &hash, StatusCode::OK).await;
            assert_eq!(body.as_ref(), payload);
            let (request, hash) = signed_request(&state, "/native/", &format!("op=open&s={SESSION}&host=localhost&port={port}"), &[], 11);
            authenticated(handle(request, state.clone()).await.unwrap(), &hash, StatusCode::FORBIDDEN).await;
            let (request, hash) = signed_request(&state, "/native/", &format!("op=close&s={SESSION}"), &[], 12);
            authenticated(handle(request, state.clone()).await.unwrap(), &hash, StatusCode::OK).await;
            assert!(state.sessions.lock().await.is_empty());
            worker.await.unwrap();
        }
    }
}
