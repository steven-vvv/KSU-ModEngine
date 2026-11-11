use std::collections::BTreeSet;
use serde::Serialize;
use sha2::{Digest, Sha256};
use crate::{Error, Result};

pub const MAX_SOURCE_BYTES: usize = 48 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Capability {
    #[serde(rename = "mem.read")] MemRead,
    #[serde(rename = "mem.write_heap")] MemWriteHeap,
    #[serde(rename = "mem.write_code")] MemWriteCode,
    #[serde(rename = "debug.hw_watchpoint")] DebugHwWatchpoint,
    #[serde(rename = "debug.uprobe")] DebugUprobe,
    #[serde(rename = "ui.menu")] UiMenu,
    #[serde(rename = "ui.canvas")] UiCanvas,
    #[serde(rename = "ui.touch_observe")] UiTouchObserve,
    #[serde(rename = "storage.kv")] StorageKv,
    #[serde(rename = "net.fetch")] NetFetch,
    #[serde(rename = "net.serve")] NetServe,
    #[serde(rename = "host.target_switch")] HostTargetSwitch,
    #[serde(rename = "script.manage")] ScriptManage,
}
impl Capability {
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "mem.read" => Self::MemRead, "mem.write_heap" => Self::MemWriteHeap,
            "mem.write_code" => Self::MemWriteCode, "debug.hw_watchpoint" => Self::DebugHwWatchpoint,
            "debug.uprobe" => Self::DebugUprobe, "ui.menu" => Self::UiMenu,
            "ui.canvas" => Self::UiCanvas, "ui.touch_observe" => Self::UiTouchObserve,
            "storage.kv" => Self::StorageKv, "net.fetch" => Self::NetFetch,
            "net.serve" => Self::NetServe, "host.target_switch" => Self::HostTargetSwitch,
            "script.manage" => Self::ScriptManage,
            _ => return Err(Error::Manifest(format!("unknown grant {value}"))),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub matches: Vec<String>,
    pub grants: BTreeSet<Capability>,
    pub connect: Vec<String>,
    #[serde(skip)]
    digest: String,
}

fn invalid(message: &str) -> Error { Error::Manifest(message.into()) }

pub(crate) fn valid_package(value: &str) -> bool { valid_identifier(value, false) }
fn valid_identifier(value: &str, hyphens: bool) -> bool {
    value.len() <= 255 && value.contains('.') && value.split('.').all(|part| {
        !part.is_empty() && part.as_bytes()[0].is_ascii_alphabetic()
            && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || (hyphens && c == b'-'))
    })
}
fn valid_domain(value: &str) -> bool {
    if value == "*" { return true; }
    let value = value.strip_prefix("*.").unwrap_or(value);
    value.len() <= 253 && value.contains('.') && value.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len()-1].is_ascii_alphanumeric()
            && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }) && !value.bytes().all(|c| c.is_ascii_digit() || c == b'.')
}

impl Manifest {
    /// Parse a line-comment header at the beginning of JS or Lua source.
    pub fn parse(source: &str) -> Result<Self> {
        if source.len() > MAX_SOURCE_BYTES { return Err(invalid("source exceeds 48 KiB")); }
        if source.contains('\0') { return Err(invalid("NUL in source")); }
        let mut lines = source.lines().skip_while(|line| line.trim().is_empty());
        let first = lines.next().ok_or_else(|| invalid("missing header"))?.trim();
        let prefix = if first == "// ==ModScript==" { "//" }
            else if first == "-- ==ModScript==" { "--" }
            else { return Err(invalid("initial ModScript comment header required")); };
        let mut id = None; let mut name = None; let mut version = None;
        let mut matches = Vec::new(); let mut grants = BTreeSet::new(); let mut connect = Vec::new();
        let mut ended = false;
        for line in lines {
            let body = line.trim().strip_prefix(prefix).ok_or_else(|| invalid("non-comment in header"))?.trim();
            if body == "==/ModScript==" { ended = true; break; }
            if body.is_empty() { continue; }
            let field = body.strip_prefix('@').ok_or_else(|| invalid("invalid header field"))?;
            let at = field.find(char::is_whitespace).ok_or_else(|| invalid("field value required"))?;
            let (key, tail) = field.split_at(at);
            let value = tail.trim();
            if value.is_empty() || value.chars().any(char::is_control) { return Err(invalid("invalid field value")); }
            match key {
                "id" | "name" | "version" => {
                    let slot = match key { "id" => &mut id, "name" => &mut name, _ => &mut version };
                    if slot.replace(value.to_owned()).is_some() { return Err(invalid("duplicate singleton field")); }
                }
                "match" => {
                    if value != "*" && !valid_package(value) { return Err(invalid("invalid package match")); }
                    if matches.iter().any(|v| v == value) { return Err(invalid("duplicate match")); }
                    matches.push(value.to_owned());
                }
                "grant" => { if !grants.insert(Capability::parse(value)?) { return Err(invalid("duplicate grant")); } }
                "connect" => {
                    if !valid_domain(value) { return Err(invalid("invalid connect domain")); }
                    let normalized = value.to_ascii_lowercase();
                    if connect.contains(&normalized) { return Err(invalid("duplicate connect domain")); }
                    connect.push(normalized);
                }
                _ => return Err(invalid("unknown header field")),
            }
        }
        if !ended { return Err(invalid("unterminated header")); }
        let id = id.ok_or_else(|| invalid("missing id"))?;
        let name = name.ok_or_else(|| invalid("missing name"))?;
        let version = version.ok_or_else(|| invalid("missing version"))?;
        if !valid_identifier(&id, true) { return Err(invalid("invalid script id")); }
        if name.len() > 256 || version.len() > 64 || version.chars().any(char::is_whitespace) { return Err(invalid("invalid name/version")); }
        if matches.is_empty() { return Err(invalid("at least one match required")); }
        Ok(Self { id, name, version, matches, grants, connect, digest: source_hash(source.as_bytes()) })
    }
}

pub fn source_hash(source: &[u8]) -> String { format!("{:x}", Sha256::digest(source)) }

#[derive(Debug, Clone)]
pub struct Authorization { grants: BTreeSet<Capability>, matches: Vec<String> }
impl Authorization {
    pub fn approve(manifest: &Manifest, source: &[u8], approved_hash: &str) -> Result<Self> {
        let denied = |s: &str| Error::Authorization(s.into());
        if source.len() > MAX_SOURCE_BYTES || source_hash(source) != approved_hash { return Err(denied("source digest does not match explicit approval")); }
        let parsed = Manifest::parse(std::str::from_utf8(source).map_err(|_| denied("source must be UTF-8 text"))?)?;
        if &parsed != manifest { return Err(denied("manifest is not bound to this exact source")); }
        if manifest.matches.iter().any(|m| m == "*") { return Err(denied("wildcard targets are not supported")); }
        if !manifest.connect.is_empty() { return Err(denied("network access is not supported")); }
        if manifest.grants.iter().any(|g| !matches!(g, Capability::MemRead | Capability::MemWriteHeap)) { return Err(denied("requested capability is not implemented in v0.1")); }
        if manifest.grants.contains(&Capability::MemWriteHeap) && !manifest.grants.contains(&Capability::MemRead) { return Err(denied("mem.write_heap requires mem.read")); }
        Ok(Self { grants: manifest.grants.clone(), matches: manifest.matches.clone() })
    }
    pub fn grants(&self) -> &BTreeSet<Capability> { &self.grants }
    pub(crate) fn permits_target(&self, package: &str) -> bool { self.matches.iter().any(|p| p == package) }
    pub(crate) fn require(&self, grant: Capability) -> Result<()> {
        if self.grants.contains(&grant) { Ok(()) } else { Err(Error::Authorization(format!("missing {grant:?}"))) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn source(grants: &str) -> String { format!("// ==ModScript==\n// @id com.test.script\n// @name Test\n// @version 1.0.0\n// @match com.example.ksumod.fixture\n{grants}// ==/ModScript==\n42;\n") }
    #[test] fn hash_known_vector() { assert_eq!(source_hash(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"); }
    #[test] fn parse_both_languages_and_approve() {
        let js = source("// @grant mem.read\n// @grant mem.write_heap\n");
        for src in [js.clone(), js.replace("//", "--")] {
            let manifest = Manifest::parse(&src).unwrap();
            assert_eq!(Authorization::approve(&manifest, src.as_bytes(), &source_hash(src.as_bytes())).unwrap().grants().len(), 2);
        }
    }
    #[test] fn reject_forged_or_changed_manifest() {
        let src = source("// @grant mem.read\n"); let mut m = Manifest::parse(&src).unwrap();
        m.grants.insert(Capability::MemWriteHeap);
        assert!(Authorization::approve(&m, src.as_bytes(), &source_hash(src.as_bytes())).is_err());
        let m = Manifest::parse(&src).unwrap(); let changed = format!("{src}\n43;");
        assert!(Authorization::approve(&m, changed.as_bytes(), &source_hash(changed.as_bytes())).is_err());
        assert!(Authorization::approve(&m, src.as_bytes(), &"0".repeat(64)).is_err());
    }
    #[test] fn strict_header_and_fields() {
        let base = source("// @grant mem.read\n");
        for src in [format!("execute();\n{base}"), base.replace("// @name Test", "// @name Test\n// @name Again"), base.replace("mem.read", "mem.typo"), base.replace("@name", "@unknown"), base.replace("com.test.script", "bad/id"), base.replace("com.example.ksumod.fixture", "com.example;exec"), base.replace("// ==/ModScript==", ""), " ".repeat(MAX_SOURCE_BYTES+1)] {
            assert!(Manifest::parse(&src).is_err(), "accepted {src:?}");
        }
    }
    #[test] fn future_permissions_parse_but_deny() {
        for grant in ["mem.write_code", "net.fetch", "host.target_switch", "ui.menu", "mem.write_heap"] {
            let src = source(&format!("// @grant {grant}\n")); let m = Manifest::parse(&src).unwrap();
            assert!(Authorization::approve(&m, src.as_bytes(), &source_hash(src.as_bytes())).is_err());
        }
        let src = source("// @grant mem.read\n").replace("@match com.example.ksumod.fixture", "@match *");
        assert!(Authorization::approve(&Manifest::parse(&src).unwrap(), src.as_bytes(), &source_hash(src.as_bytes())).is_err());
    }
    #[test] fn domains_are_not_urls_or_injection() {
        for domain in ["https://example.com", "example.com:80", "127.0.0.1", "a..com", "-x.com", "evil.com/path"] {
            assert!(Manifest::parse(&source(&format!("// @connect {domain}\n"))).is_err());
        }
        let src = source("// @connect *.example.com\n");
        assert!(Authorization::approve(&Manifest::parse(&src).unwrap(), src.as_bytes(), &source_hash(src.as_bytes())).is_err());
    }
}
