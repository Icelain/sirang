//! Tunnel groups for reverst-style reverse HTTP load balancing.
//!
//! Clients register into a named group; the remote HTTP listener routes by
//! Host / X-Forwarded-Host and picks a registered client via round-robin.

use crate::errors::GenericError;
use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// A registered local client connection (shared for concurrent stream opens).
pub type SharedConnection = Arc<Mutex<s2n_quic::Connection>>;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GroupsFile {
    pub groups: HashMap<String, GroupConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct GroupConfig {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub authentication: AuthConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    pub basic: Option<BasicAuth>,
    pub bearer: Option<BearerAuth>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BearerAuth {
    pub token: String,
}

#[derive(Clone)]
pub struct TunnelGroups {
    /// group name -> config
    configs: HashMap<String, GroupConfig>,
    /// host (lowercase) -> group name
    host_index: HashMap<String, String>,
    /// group name -> round-robin clients
    clients: Arc<Mutex<HashMap<String, ClientPool>>>,
}

struct ClientPool {
    entries: Vec<SharedConnection>,
    next: AtomicUsize,
}

impl TunnelGroups {
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let raw = std::fs::read_to_string(path)?;
        let file: GroupsFile = serde_yaml::from_str(&raw)?;
        Ok(Self::from_configs(file.groups))
    }

    /// Single default group for quick local setups (reverst "localhost" style).
    pub fn single_group(name: &str, hosts: Vec<String>, auth: AuthConfig) -> Self {
        let mut groups = HashMap::new();
        groups.insert(
            name.to_string(),
            GroupConfig {
                hosts,
                authentication: auth,
            },
        );
        Self::from_configs(groups)
    }

    fn from_configs(configs: HashMap<String, GroupConfig>) -> Self {
        let mut host_index = HashMap::new();
        let mut clients = HashMap::new();
        for (name, cfg) in &configs {
            clients.insert(
                name.clone(),
                ClientPool {
                    entries: Vec::new(),
                    next: AtomicUsize::new(0),
                },
            );
            for host in &cfg.hosts {
                host_index.insert(host.to_ascii_lowercase(), name.clone());
            }
            // Always allow addressing the group by its own name as host.
            host_index
                .entry(name.to_ascii_lowercase())
                .or_insert_with(|| name.clone());
        }
        Self {
            configs,
            host_index,
            clients: Arc::new(Mutex::new(clients)),
        }
    }

    pub fn group_names(&self) -> Vec<String> {
        self.configs.keys().cloned().collect()
    }

    pub fn resolve_group(&self, host: &str) -> Option<String> {
        let host = host_only(host);
        self.host_index.get(&host.to_ascii_lowercase()).cloned()
    }

    pub fn authenticate(&self, group: &str, authorization: Option<&str>) -> Result<(), String> {
        let cfg = self
            .configs
            .get(group)
            .ok_or_else(|| format!("unknown tunnel group {group:?}"))?;

        let auth = &cfg.authentication;
        let needs_auth = auth.basic.is_some() || auth.bearer.is_some();
        if !needs_auth {
            return Ok(());
        }

        let header = authorization.ok_or_else(|| "missing authorization".to_string())?;
        let (scheme, payload) = header
            .split_once(' ')
            .ok_or_else(|| "malformed authorization".to_string())?;

        if let Some(basic) = &auth.basic {
            if scheme.eq_ignore_ascii_case("Basic") {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(payload.trim())
                    .map_err(|_| "invalid basic credentials encoding".to_string())?;
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| "invalid basic credentials encoding".to_string())?;
                let (user, pass) = decoded
                    .split_once(':')
                    .ok_or_else(|| "invalid basic credentials format".to_string())?;
                if user == basic.username && pass == basic.password {
                    return Ok(());
                }
                return Err("unauthorized".to_string());
            }
        }

        if let Some(bearer) = &auth.bearer {
            if scheme.eq_ignore_ascii_case("Bearer") && payload.trim() == bearer.token {
                return Ok(());
            }
        }

        Err("unauthorized".to_string())
    }

    pub async fn register(&self, group: &str, conn: SharedConnection) -> Result<(), String> {
        let mut map = self.clients.lock().await;
        let pool = map
            .get_mut(group)
            .ok_or_else(|| format!("unknown tunnel group {group:?}"))?;
        pool.entries.push(conn);
        log::info!(
            "Client registered on group {group} ({} active)",
            pool.entries.len()
        );
        Ok(())
    }

    pub async fn unregister(&self, group: &str, conn: &SharedConnection) {
        let mut map = self.clients.lock().await;
        if let Some(pool) = map.get_mut(group) {
            pool.entries.retain(|c| !Arc::ptr_eq(c, conn));
            log::info!(
                "Client left group {group} ({} active)",
                pool.entries.len()
            );
        }
    }

    /// Round-robin next client for a group.
    pub async fn next_client(&self, group: &str) -> Option<SharedConnection> {
        let map = self.clients.lock().await;
        let pool = map.get(group)?;
        if pool.entries.is_empty() {
            return None;
        }
        let i = pool.next.fetch_add(1, Ordering::Relaxed) % pool.entries.len();
        Some(pool.entries[i].clone())
    }
}

fn host_only(host: &str) -> &str {
    // strip port if present (but not IPv6 brackets for simplicity on hostnames)
    if let Some((h, _)) = host.rsplit_once(':') {
        if !host.starts_with('[') && h.chars().all(|c| c.is_ascii_digit() || c == '.') {
            // might be ipv4:port
            return h;
        }
        if host.starts_with('[') {
            return host;
        }
        // hostname:port
        if !h.is_empty() && !h.contains(']') {
            return h;
        }
    }
    host
}

/// Parse `REGISTER <group>[ <scheme> <payload>]` line from the registration stream.
pub fn parse_register_line(line: &str) -> Result<(String, Option<String>), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let line = line.trim();
    let rest = line
        .strip_prefix("REGISTER ")
        .ok_or_else(|| GenericError("expected REGISTER command".into()))?;
    let mut parts = rest.splitn(3, ' ');
    let group = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GenericError("missing group name".into()))?
        .to_string();
    let scheme = parts.next();
    let payload = parts.next();
    let authorization = match (scheme, payload) {
        (Some(s), Some(p)) => Some(format!("{s} {p}")),
        (Some(_), None) => {
            return Err(Box::new(GenericError(
                "REGISTER auth requires scheme and payload".into(),
            )))
        }
        _ => None,
    };
    Ok((group, authorization))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_register() {
        let (g, a) = parse_register_line("REGISTER localhost").unwrap();
        assert_eq!(g, "localhost");
        assert!(a.is_none());

        let (g, a) = parse_register_line("REGISTER g Basic dXNlcjpwYXNz").unwrap();
        assert_eq!(g, "g");
        assert_eq!(a.as_deref(), Some("Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn test_auth_basic() {
        let groups = TunnelGroups::single_group(
            "localhost",
            vec!["localhost".into()],
            AuthConfig {
                basic: Some(BasicAuth {
                    username: "user".into(),
                    password: "pass".into(),
                }),
                bearer: None,
            },
        );
        let cred = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert!(groups
            .authenticate("localhost", Some(&format!("Basic {cred}")))
            .is_ok());
        assert!(groups.authenticate("localhost", None).is_err());
    }

    #[test]
    fn test_host_resolve() {
        let groups = TunnelGroups::single_group(
            "app",
            vec!["example.test".into(), "localhost".into()],
            AuthConfig::default(),
        );
        assert_eq!(groups.resolve_group("example.test").as_deref(), Some("app"));
        assert_eq!(groups.resolve_group("localhost:8181").as_deref(), Some("app"));
    }
}
