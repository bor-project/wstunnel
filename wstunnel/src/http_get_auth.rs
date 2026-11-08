use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, StatusCode};
use ring::{digest, hkdf, hmac, rand::{SecureRandom, SystemRandom}};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(crate) const VERSION: &str = "2";
const MAX_AGE: u64 = 30_000;
const MAX_FUTURE: u64 = 5_000;
const MAX_REPLAYS: usize = 262_144;

pub(crate) fn hash(data: &[u8]) -> [u8; 32] {
    digest::digest(&digest::SHA256, data).as_ref().try_into().unwrap()
}

pub(crate) fn hex(data: &[u8]) -> String {
    data.iter().map(|value| format!("{value:02x}")).collect()
}

pub(crate) fn unhex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 { return None; }
    let mut result = [0; N];
    for (target, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *target = (pair[0] as char).to_digit(16)? as u8 * 16 + (pair[1] as char).to_digit(16)? as u8;
    }
    Some(result)
}

fn put(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn sign(key: &hmac::Key, data: &[u8]) -> String {
    STANDARD.encode(hmac::sign(key, data).as_ref())
}

fn verify(key: &hmac::Key, data: &[u8], signature: &str) -> bool {
    let Ok(decoded) = STANDARD.decode(signature) else { return false; };
    decoded.len() == 32 && STANDARD.encode(&decoded) == signature && hmac::verify(key, data, &decoded).is_ok()
}

pub(crate) struct Keys {
    pub(crate) id: [u8; 32],
    pub(crate) identity: String,
    request: hmac::Key,
    response: hmac::Key,
    challenge: hmac::Key,
}

impl Keys {
    pub(crate) fn derive(credential: &str) -> Option<Self> {
        let id = uuid::Uuid::parse_str(credential).ok()?;
        if id.is_nil() { return None; }
        let secret = id.to_string();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"amneziageo.http-get.v2");
        let root = salt.extract(secret.as_bytes());
        let derive = |purpose: &[u8]| -> Option<hmac::Key> {
            let info = [purpose];
            let output = root.expand(&info, hkdf::HKDF_SHA256).ok()?;
            let mut key = [0; 32];
            output.fill(&mut key).ok()?;
            Some(hmac::Key::new(hmac::HMAC_SHA256, &key))
        };
        let mut identity = b"amneziageo.http-get.id.v2\0".to_vec();
        identity.extend_from_slice(secret.as_bytes());
        let id = hash(&identity);
        Some(Self { id, identity: hex(&id), request: derive(b"request")?, response: derive(b"response")?, challenge: derive(b"challenge")? })
    }

    fn challenge_message(&self, path: &str, nonce: &[u8; 16], epoch: &[u8; 16], time: u64) -> Vec<u8> {
        let mut data = Vec::new();
        put(&mut data, b"amneziageo.http-get.challenge.v2");
        put(&mut data, path.as_bytes());
        put(&mut data, &self.id);
        put(&mut data, nonce);
        put(&mut data, epoch);
        data.extend_from_slice(&time.to_be_bytes());
        data
    }

    pub(crate) fn challenge(&self, path: &str, nonce: &[u8; 16], epoch: &[u8; 16], time: u64) -> String {
        sign(&self.challenge, &self.challenge_message(path, nonce, epoch, time))
    }

    fn request_message(&self, method: &str, path: &str, query: &BTreeMap<String, String>, payload: &[u8], stamp: &Stamp) -> Option<Vec<u8>> {
        if method != "GET" || !path.starts_with('/') || path.len() > 1024 || query.len() > 32
            || query.iter().any(|(name,value)| name.is_empty() || name.len() > 64 || value.len() > 1024) { return None; }
        let mut data = Vec::new();
        put(&mut data, b"amneziageo.http-get.request.v2");
        put(&mut data, method.as_bytes());
        put(&mut data, path.as_bytes());
        put(&mut data, &self.id);
        put(&mut data, &stamp.epoch);
        data.extend_from_slice(&stamp.time.to_be_bytes());
        put(&mut data, &stamp.nonce);
        data.extend_from_slice(&(query.len() as u16).to_be_bytes());
        for (name,value) in query {
            put(&mut data, name.as_bytes());
            put(&mut data, value.as_bytes());
        }
        put(&mut data, &hash(payload));
        Some(data)
    }

    pub(crate) fn verify_request(&self, method: &str, path: &str, query: &BTreeMap<String, String>, payload: &[u8], stamp: &Stamp, signature: &str) -> Option<[u8; 32]> {
        let data = self.request_message(method, path, query, payload, stamp)?;
        verify(&self.request, &data, signature).then(|| hash(&data))
    }

    pub(crate) fn response(&self, request: &[u8; 32], value: Response<'_>) -> String {
        let mut data = Vec::new();
        put(&mut data, b"amneziageo.http-get.response.v2");
        put(&mut data, request);
        data.extend_from_slice(&value.status.as_u16().to_be_bytes());
        put(&mut data, value.epoch);
        data.extend_from_slice(&value.time.to_be_bytes());
        for field in [value.version,value.sequence,value.dropped,value.fault] { put(&mut data, field.as_bytes()); }
        put(&mut data, &hash(value.body));
        sign(&self.response, &data)
    }
}

pub(crate) struct Stamp {
    pub(crate) epoch: [u8; 16],
    pub(crate) time: u64,
    pub(crate) nonce: [u8; 16],
}

pub(crate) struct Response<'a> {
    pub(crate) status: StatusCode,
    pub(crate) epoch: &'a [u8; 16],
    pub(crate) time: u64,
    pub(crate) version: &'a str,
    pub(crate) sequence: &'a str,
    pub(crate) dropped: &'a str,
    pub(crate) fault: &'a str,
    pub(crate) body: &'a [u8],
}

pub(crate) fn one<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() { return None; }
    Some(value)
}

type ReplayId = ([u8; 32], [u8; 16]);

struct Replay {
    values: HashMap<ReplayId, u64>,
    expiry: BinaryHeap<Reverse<(u64, ReplayId)>>,
    capacity: usize,
}

impl Replay {
    fn accept(&mut self, key: ReplayId, expiry: u64, now: u64) -> Result<(), &'static str> {
        while self.expiry.peek().is_some_and(|entry| entry.0.0 <= now) {
            let Reverse((deadline,key)) = self.expiry.pop().unwrap();
            if self.values.get(&key) == Some(&deadline) { self.values.remove(&key); }
        }
        if self.values.contains_key(&key) { return Err("replay"); }
        if self.values.len() >= self.capacity { return Err("busy"); }
        self.values.insert(key, expiry);
        self.expiry.push(Reverse((expiry, key)));
        Ok(())
    }
}

pub(crate) struct Verified {
    pub(crate) keys: Arc<Keys>,
    pub(crate) request: [u8; 32],
}

pub(crate) struct Failure {
    pub(crate) status: StatusCode,
    pub(crate) fault: &'static str,
    pub(crate) verified: Option<Verified>,
}

impl Failure {
    fn unsigned(status: StatusCode) -> Self { Self { status, fault: "", verified: None } }
}

pub(crate) struct Guard {
    pub(crate) epoch: [u8; 16],
    started: Instant,
    users: HashMap<[u8; 32], Arc<Keys>>,
    replay: Mutex<Replay>,
}

impl Guard {
    pub(crate) fn new(credentials: &HashSet<String>) -> anyhow::Result<Self> {
        let mut epoch = [0; 16];
        SystemRandom::new().fill(&mut epoch).map_err(|_| anyhow::anyhow!("HTTP GET entropy unavailable"))?;
        let mut users = HashMap::new();
        for credential in credentials {
            let key = Keys::derive(credential).ok_or_else(|| anyhow::anyhow!("invalid HTTP GET signing key"))?;
            if users.insert(key.id, Arc::new(key)).is_some() { anyhow::bail!("duplicate HTTP GET signing key"); }
        }
        Ok(Self { epoch, started: Instant::now(), users,
            replay: Mutex::new(Replay { values: HashMap::new(), expiry: BinaryHeap::new(), capacity: MAX_REPLAYS }) })
    }

    pub(crate) fn time(&self) -> u64 { self.started.elapsed().as_millis() as u64 }

    fn key(&self, headers: &HeaderMap) -> Option<Arc<Keys>> {
        let id = unhex::<32>(one(headers, "x-wg-key")?)?;
        self.users.get(&id).cloned()
    }

    pub(crate) fn challenge(&self, headers: &HeaderMap, path: &str, nonce: &str) -> Option<(Vec<u8>, String)> {
        if one(headers, "x-wg-version") != Some(VERSION) || headers.contains_key("authorization") { return None; }
        let keys = self.key(headers)?;
        let nonce = unhex::<16>(nonce)?;
        let time = self.time();
        let body = serde_json::to_vec(&serde_json::json!({ "epoch": hex(&self.epoch), "time": time })).ok()?;
        Some((body, keys.challenge(path, &nonce, &self.epoch, time)))
    }

    pub(crate) fn authorize(&self, headers: &HeaderMap, method: &str, path: &str, query: &BTreeMap<String, String>, payload: &[u8]) -> Result<Verified, Failure> {
        self.authorize_at(headers, method, path, query, payload, self.time())
    }

    fn authorize_at(&self, headers: &HeaderMap, method: &str, path: &str, query: &BTreeMap<String, String>, payload: &[u8], now: u64) -> Result<Verified, Failure> {
        let unauthorized = || Failure::unsigned(StatusCode::UNAUTHORIZED);
        if one(headers,"x-wg-version") != Some(VERSION) || headers.contains_key("authorization") {
            return Err(Failure::unsigned(StatusCode::UPGRADE_REQUIRED));
        }
        let keys = self.key(headers).ok_or_else(unauthorized)?;
        let stamp = Stamp {
            epoch: one(headers,"x-wg-epoch").and_then(unhex::<16>).ok_or_else(unauthorized)?,
            time: one(headers,"x-wg-time").and_then(|value| value.parse().ok()).ok_or_else(unauthorized)?,
            nonce: one(headers,"x-wg-nonce").and_then(unhex::<16>).ok_or_else(unauthorized)?,
        };
        let signature = one(headers,"x-wg-auth").ok_or_else(unauthorized)?;
        let request = keys.verify_request(method,path,query,payload,&stamp,signature).ok_or_else(unauthorized)?;
        let verified = Verified { keys, request };
        let failure = |verified,fault,status| Failure { fault,status,verified:Some(verified) };
        if stamp.epoch != self.epoch { return Err(failure(verified,"epoch",StatusCode::CONFLICT)); }
        if stamp.time > now.saturating_add(MAX_FUTURE) || now.saturating_sub(stamp.time) > MAX_AGE {
            return Err(failure(verified,"clock",StatusCode::CONFLICT));
        }
        let Ok(mut replay) = self.replay.lock() else { return Err(failure(verified,"busy",StatusCode::SERVICE_UNAVAILABLE)); };
        if let Err(fault) = replay.accept((verified.keys.id,stamp.nonce),stamp.time.saturating_add(MAX_AGE + 1),now) {
            return Err(failure(verified,fault,if fault == "busy" { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::CONFLICT }));
        }
        Ok(verified)
    }
}

pub(crate) fn query(raw: &str) -> Option<BTreeMap<String,String>> {
    if raw.len() > 4096 { return None; }
    let bytes = raw.as_bytes();
    for (index,value) in bytes.iter().enumerate() {
        if *value == b'%' && (index + 2 >= bytes.len() || !bytes[index + 1].is_ascii_hexdigit() || !bytes[index + 2].is_ascii_hexdigit()) { return None; }
    }
    let mut query = BTreeMap::new();
    for (name,value) in url::form_urlencoded::parse(bytes) {
        if name.is_empty() || name.len() > 64 || value.len() > 1024 || !name.is_ascii() || !value.is_ascii()
            || name.bytes().chain(value.bytes()).any(|byte| byte < 32 || byte == 127)
            || query.insert(name.into_owned(),value.into_owned()).is_some() { return None; }
    }
    (query.len() <= 32).then_some(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn fixture() -> Value { serde_json::from_str(include_str!("../tests/http_get_auth_vectors.json")).unwrap() }

    fn data_hex(value: &str) -> Vec<u8> {
        value.as_bytes().chunks_exact(2).map(|pair| (pair[0] as char).to_digit(16).unwrap() as u8 * 16 + (pair[1] as char).to_digit(16).unwrap() as u8).collect()
    }

    fn fields(keys: &Keys, epoch: [u8;16], time: u64, nonce: [u8;16], query: &BTreeMap<String,String>) -> HeaderMap {
        let stamp = Stamp {epoch,time,nonce};
        let message = keys.request_message("GET","/native/",query,&[],&stamp).unwrap();
        let mut headers = HeaderMap::new();
        for (name,value) in [("x-wg-version",VERSION.to_string()),("x-wg-key",keys.identity.clone()),("x-wg-epoch",hex(&epoch)),
            ("x-wg-time",time.to_string()),("x-wg-nonce",hex(&nonce)),("x-wg-auth",sign(&keys.request,&message))] {
            headers.insert(hyper::header::HeaderName::from_static(name),value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn independent_python_vectors_match() {
        let v=fixture();let keys=Keys::derive(v["credential"].as_str().unwrap()).unwrap();
        let epoch=unhex::<16>(v["epochHex"].as_str().unwrap()).unwrap();
        let nonce=unhex::<16>(v["nonceHex"].as_str().unwrap()).unwrap();
        let stamp=Stamp {epoch,nonce,time:v["time"].as_u64().unwrap()};
        let query:BTreeMap<String,String>=serde_json::from_value(v["query"].clone()).unwrap();
        let payload=data_hex(v["dataHex"].as_str().unwrap());
        let path=v["path"].as_str().unwrap();
        assert_eq!(keys.identity,v["keyId"].as_str().unwrap());
        let message=keys.request_message("GET",path,&query,&payload,&stamp).unwrap();
        assert_eq!(hex(&hash(&message)),v["requestHashHex"].as_str().unwrap());
        assert_eq!(sign(&keys.request,&message),v["requestMac"].as_str().unwrap());
        assert_eq!(keys.challenge(path,&nonce,&epoch,stamp.time),v["challengeMac"].as_str().unwrap());
        assert!(keys.verify_request("GET",path,&query,&payload,&stamp,v["requestMac"].as_str().unwrap()).is_some());
        let response=Response {status:StatusCode::OK,epoch:&epoch,time:123499,version:VERSION,sequence:"7",dropped:"12",fault:"",body:&[]};
        assert_eq!(keys.response(&hash(&message),response),v["responseMac"].as_str().unwrap());
        let mut wrong=payload.clone();wrong[0]^=1;
        assert!(keys.verify_request("GET",path,&query,&wrong,&stamp,v["requestMac"].as_str().unwrap()).is_none());
    }

    #[test]
    fn duplicate_and_invalid_queries_are_rejected() {
        for value in ["op=open&op=pull","x=%zz","x=%","x=%ff","x=%0a","=value"] { assert!(query(value).is_none()); }
        assert_eq!(query("z=two&a=one"),query("a=one&z=two"));
    }

    #[test]
    fn replay_clock_and_server_restart_are_rejected() {
        let credentials=HashSet::from([fixture()["credential"].as_str().unwrap().to_string()]);
        let guard=Guard::new(&credentials).unwrap();let keys=Keys::derive(credentials.iter().next().unwrap()).unwrap();
        let params=query("op=open&s=0123456789abcdef0123456789abcdef").unwrap();
        let headers=fields(&keys,guard.epoch,1_000,[1;16],&params);
        assert!(guard.authorize_at(&headers,"GET","/native/",&params,&[],1_000).is_ok());
        let duplicate=guard.authorize_at(&headers,"GET","/native/",&params,&[],1_000);
        assert!(matches!(duplicate,Err(Failure{fault:"replay",verified:Some(_),..})));
        let restart=Guard::new(&credentials).unwrap();
        assert!(matches!(restart.authorize_at(&headers,"GET","/native/",&params,&[],1_000),Err(Failure{fault:"epoch",..})));
        assert!(matches!(guard.authorize_at(&headers,"GET","/native/",&params,&[],31_001),Err(Failure{fault:"clock",..})));
        let future=fields(&keys,guard.epoch,6_001,[2;16],&params);
        assert!(matches!(guard.authorize_at(&future,"GET","/native/",&params,&[],1_000),Err(Failure{fault:"clock",..})));
    }

    #[test]
    fn last_valid_millisecond_still_rejects_replay() {
        let credentials=HashSet::from([fixture()["credential"].as_str().unwrap().to_string()]);
        let guard=Guard::new(&credentials).unwrap();let keys=Keys::derive(credentials.iter().next().unwrap()).unwrap();
        let params=query("op=open").unwrap();let headers=fields(&keys,guard.epoch,0,[3;16],&params);
        assert!(guard.authorize_at(&headers,"GET","/native/",&params,&[],30_000).is_ok());
        assert!(matches!(guard.authorize_at(&headers,"GET","/native/",&params,&[],30_000),Err(Failure{fault:"replay",..})));
    }

    #[test]
    fn full_cache_keeps_unexpired_nonce_and_recovers_after_expiry() {
        let credentials=HashSet::from([fixture()["credential"].as_str().unwrap().to_string()]);
        let guard=Guard::new(&credentials).unwrap();guard.replay.lock().unwrap().capacity=1;
        let keys=Keys::derive(credentials.iter().next().unwrap()).unwrap();let params=query("op=open").unwrap();
        let first=fields(&keys,guard.epoch,0,[4;16],&params);let next=fields(&keys,guard.epoch,1,[5;16],&params);
        assert!(guard.authorize_at(&first,"GET","/native/",&params,&[],0).is_ok());
        assert!(matches!(guard.authorize_at(&next,"GET","/native/",&params,&[],1),Err(Failure{fault:"busy",..})));
        assert!(matches!(guard.authorize_at(&first,"GET","/native/",&params,&[],1),Err(Failure{fault:"replay",..})));
        let fresh=fields(&keys,guard.epoch,30_001,[6;16],&params);
        assert!(guard.authorize_at(&fresh,"GET","/native/",&params,&[],30_001).is_ok());
    }

    #[test]
    fn concurrent_copies_authorize_exactly_once() {
        let credentials=HashSet::from([fixture()["credential"].as_str().unwrap().to_string()]);
        let guard=Arc::new(Guard::new(&credentials).unwrap());let keys=Keys::derive(credentials.iter().next().unwrap()).unwrap();
        let params=query("op=open").unwrap();let headers=fields(&keys,guard.epoch,0,[7;16],&params);
        let barrier=Arc::new(std::sync::Barrier::new(8));let mut workers=Vec::new();
        for _ in 0..8 {
            let guard=guard.clone();let barrier=barrier.clone();let headers=headers.clone();let params=params.clone();
            workers.push(std::thread::spawn(move|| {barrier.wait();guard.authorize_at(&headers,"GET","/native/",&params,&[],0).is_ok()}));
        }
        assert_eq!(workers.into_iter().filter_map(|worker|worker.join().ok()).filter(|accepted|*accepted).count(),1);
    }
}
