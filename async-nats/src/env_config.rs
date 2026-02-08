// Copyright 2020-2022 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Internal module for loading ConnectOptions from environment variables.

use crate::ConnectOptions;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

/// Environment variable names for NATS configuration
pub(crate) mod env_keys {
    // Authentication
    pub(crate) const NATS_CREDS_FILE: &str = "NATS_CREDS_FILE";
    pub(crate) const NATS_NKEY: &str = "NATS_NKEY";
    pub(crate) const NATS_USER: &str = "NATS_USER";
    pub(crate) const NATS_PASSWORD: &str = "NATS_PASSWORD";
    pub(crate) const NATS_PASSWORD_FILE: &str = "NATS_PASSWORD_FILE";
    pub(crate) const NATS_TOKEN: &str = "NATS_TOKEN";
    pub(crate) const NATS_TOKEN_FILE: &str = "NATS_TOKEN_FILE";

    // TLS
    pub(crate) const NATS_TLS_CERT: &str = "NATS_TLS_CERT";
    pub(crate) const NATS_TLS_KEY: &str = "NATS_TLS_KEY";
    pub(crate) const NATS_TLS_CA_CERT: &str = "NATS_TLS_CA_CERT";
    pub(crate) const NATS_REQUIRE_TLS: &str = "NATS_REQUIRE_TLS";
    pub(crate) const NATS_TLS_FIRST: &str = "NATS_TLS_FIRST";

    // Connection
    pub(crate) const NATS_CLIENT_NAME: &str = "NATS_CLIENT_NAME";
    pub(crate) const NATS_CONNECTION_TIMEOUT_SECS: &str = "NATS_CONNECTION_TIMEOUT_SECS";
    pub(crate) const NATS_REQUEST_TIMEOUT_SECS: &str = "NATS_REQUEST_TIMEOUT_SECS";
    pub(crate) const NATS_PING_INTERVAL_SECS: &str = "NATS_PING_INTERVAL_SECS";
    pub(crate) const NATS_MAX_RECONNECTS: &str = "NATS_MAX_RECONNECTS";
    pub(crate) const NATS_NO_ECHO: &str = "NATS_NO_ECHO";
}

/// Trait for parsing environment variable values into typed values.
trait EnvParser: Sized {
    fn parse(value: &str) -> Option<Self>;
}

impl EnvParser for String {
    fn parse(value: &str) -> Option<Self> {
        Some(value.to_string())
    }
}

impl EnvParser for bool {
    fn parse(_: &str) -> Option<Self> {
        Some(true)
    }
}

impl EnvParser for u64 {
    fn parse(value: &str) -> Option<Self> {
        value.parse().ok()
    }
}

impl EnvParser for Duration {
    fn parse(value: &str) -> Option<Self> {
        value.parse::<u64>().ok().map(Duration::from_secs)
    }
}

impl EnvParser for PathBuf {
    fn parse(value: &str) -> Option<Self> {
        Some(PathBuf::from(value))
    }
}

/// Load and parse an environment variable.
fn load_env<T: EnvParser>(key: &str) -> Option<T> {
    env::var(key).ok().and_then(|v| T::parse(&v))
}

/// Load a string value from either an inline env var or a file.
/// Inline value takes priority over file.
async fn load_string_or_file(inline_key: &str, file_key: &str) -> std::io::Result<Option<String>> {
    // Inline value takes priority
    if let Ok(value) = env::var(inline_key) {
        return Ok(Some(value));
    }

    // Try file-based value
    if let Ok(file_path) = env::var(file_key) {
        let content = tokio::fs::read_to_string(&file_path).await.map_err(|err| {
            std::io::Error::other(format!("reading {} from '{}': {}", file_key, file_path, err))
        })?;
        return Ok(Some(content.trim().to_string()));
    }

    Ok(None)
}

/// Apply a function if an environment variable is set and parses successfully.
fn apply_env<T: EnvParser, F>(key: &str, mut opts: ConnectOptions, f: F) -> ConnectOptions
where
    F: FnOnce(ConnectOptions, T) -> ConnectOptions,
{
    if let Some(value) = load_env::<T>(key) {
        opts = f(opts, value);
    }
    opts
}

/// Load all environment variables into ConnectOptions.
pub(crate) async fn apply_env_config(mut opts: ConnectOptions) -> std::io::Result<ConnectOptions> {
    // Authentication - check in priority order
    if let Some(path) = load_env::<PathBuf>(env_keys::NATS_CREDS_FILE) {
        return opts.credentials_file(&path).await;
    }

    if let Some(nkey) = load_env::<String>(env_keys::NATS_NKEY) {
        opts.auth.nkey = Some(nkey);
        return Ok(opts);
    }

    if let (Some(user), Some(password)) = (
        load_env::<String>(env_keys::NATS_USER),
        load_string_or_file(env_keys::NATS_PASSWORD, env_keys::NATS_PASSWORD_FILE).await?,
    ) {
        opts.auth.username = Some(user);
        opts.auth.password = Some(password);
        return Ok(opts);
    }

    if let Some(token) = load_string_or_file(env_keys::NATS_TOKEN, env_keys::NATS_TOKEN_FILE).await? {
        opts.auth.token = Some(token);
    }

    // TLS - client certificate and key
    if let (Some(cert), Some(key)) = (
        load_env::<PathBuf>(env_keys::NATS_TLS_CERT),
        load_env::<PathBuf>(env_keys::NATS_TLS_KEY),
    ) {
        opts = opts.add_client_certificate(cert, key);
    }

    // CA certificate
    if let Some(ca_cert) = load_env::<PathBuf>(env_keys::NATS_TLS_CA_CERT) {
        opts = opts.add_root_certificates(ca_cert);
    }

    // TLS flags
    if load_env::<bool>(env_keys::NATS_REQUIRE_TLS).is_some() {
        opts = opts.require_tls(true);
    }

    if load_env::<bool>(env_keys::NATS_TLS_FIRST).is_some() {
        opts = opts.tls_first();
    }

    // Connection settings
    opts = apply_env(env_keys::NATS_CLIENT_NAME, opts, |opts, name: String| {
        opts.name(name)
    });

    opts = apply_env(
        env_keys::NATS_CONNECTION_TIMEOUT_SECS,
        opts,
        |opts, timeout: Duration| opts.connection_timeout(timeout),
    );

    opts = apply_env(
        env_keys::NATS_REQUEST_TIMEOUT_SECS,
        opts,
        |opts, timeout: Duration| opts.request_timeout(Some(timeout)),
    );

    opts = apply_env(
        env_keys::NATS_PING_INTERVAL_SECS,
        opts,
        |opts, interval: Duration| opts.ping_interval(interval),
    );

    opts = apply_env(env_keys::NATS_MAX_RECONNECTS, opts, |opts, count: u64| {
        opts.max_reconnects(count as usize)
    });

    if load_env::<bool>(env_keys::NATS_NO_ECHO).is_some() {
        opts = opts.no_echo();
    }

    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to safely manage environment variables in tests
    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = env::var(key).ok();
            env::set_var(key, value);
            EnvGuard { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(original) = &self.original {
                env::set_var(self.key, original);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[tokio::test]
    async fn test_from_env_no_vars() {
        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert!(opts.auth.token.is_none());
        assert!(opts.auth.nkey.is_none());
        assert!(opts.auth.username.is_none());
    }

    #[tokio::test]
    async fn test_from_env_token() {
        let _token = EnvGuard::set(env_keys::NATS_TOKEN, "test_token");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.token, Some("test_token".to_string()));
    }

    #[tokio::test]
    async fn test_from_env_user_password() {
        let _user = EnvGuard::set(env_keys::NATS_USER, "alice");
        let _pass = EnvGuard::set(env_keys::NATS_PASSWORD, "secret");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.username, Some("alice".to_string()));
        assert_eq!(opts.auth.password, Some("secret".to_string()));
    }

    #[tokio::test]
    async fn test_from_env_user_password_requires_both() {
        let _user = EnvGuard::set(env_keys::NATS_USER, "alice");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert!(opts.auth.username.is_none());
        assert!(opts.auth.password.is_none());
    }

    #[tokio::test]
    async fn test_from_env_nkey() {
        let _nkey = EnvGuard::set(env_keys::NATS_NKEY, "SUAIO3FHUX5PNV2LQIIP7TZ3N4L7TX3W53MQGEIVYFIGA635OZCKEYHFLM");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.nkey, Some("SUAIO3FHUX5PNV2LQIIP7TZ3N4L7TX3W53MQGEIVYFIGA635OZCKEYHFLM".to_string()));
    }

    #[tokio::test]
    async fn test_from_env_auth_priority_nkey_over_token() {
        let _nkey = EnvGuard::set(env_keys::NATS_NKEY, "test_nkey");
        let _token = EnvGuard::set(env_keys::NATS_TOKEN, "test_token");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.nkey, Some("test_nkey".to_string()));
        assert!(opts.auth.token.is_none());
    }

    #[tokio::test]
    async fn test_from_env_auth_priority_user_pass_over_token() {
        let _user = EnvGuard::set(env_keys::NATS_USER, "alice");
        let _pass = EnvGuard::set(env_keys::NATS_PASSWORD, "secret");
        let _token = EnvGuard::set(env_keys::NATS_TOKEN, "test_token");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.username, Some("alice".to_string()));
        assert!(opts.auth.token.is_none());
    }

    #[tokio::test]
    async fn test_from_env_connection_timeout() {
        let _timeout = EnvGuard::set(env_keys::NATS_CONNECTION_TIMEOUT_SECS, "30");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.connection_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_from_env_connection_timeout_invalid() {
        let _timeout = EnvGuard::set(env_keys::NATS_CONNECTION_TIMEOUT_SECS, "not_a_number");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        // Should use default (5 secs), not panic
        assert_eq!(opts.connection_timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_from_env_client_name() {
        let _name = EnvGuard::set(env_keys::NATS_CLIENT_NAME, "test_client");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.name, Some("test_client".to_string()));
    }

    #[tokio::test]
    async fn test_from_env_no_echo() {
        let _no_echo = EnvGuard::set(env_keys::NATS_NO_ECHO, "1");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert!(opts.no_echo);
    }

    #[tokio::test]
    async fn test_from_env_request_timeout() {
        let _timeout = EnvGuard::set(env_keys::NATS_REQUEST_TIMEOUT_SECS, "15");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.request_timeout, Some(Duration::from_secs(15)));
    }

    #[tokio::test]
    async fn test_from_env_ping_interval() {
        let _interval = EnvGuard::set(env_keys::NATS_PING_INTERVAL_SECS, "20");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.ping_interval, Duration::from_secs(20));
    }

    #[tokio::test]
    async fn test_from_env_max_reconnects() {
        let _max = EnvGuard::set(env_keys::NATS_MAX_RECONNECTS, "10");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.max_reconnects, Some(10));
    }

    #[tokio::test]
    async fn test_from_env_tls_require() {
        let _require = EnvGuard::set(env_keys::NATS_REQUIRE_TLS, "1");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert!(opts.tls_required);
    }

    #[tokio::test]
    async fn test_from_env_tls_first() {
        let _first = EnvGuard::set(env_keys::NATS_TLS_FIRST, "1");

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert!(opts.tls_first);
    }

    #[tokio::test]
    async fn test_from_env_token_from_file() {
        let token_file = "/tmp/test_nats_token_file.txt";
        tokio::fs::write(token_file, "token_from_file").await.unwrap();

        let _token_file = EnvGuard::set(env_keys::NATS_TOKEN_FILE, token_file);

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.token, Some("token_from_file".to_string()));

        let _ = tokio::fs::remove_file(token_file).await;
    }

    #[tokio::test]
    async fn test_from_env_token_inline_priority_over_file() {
        let token_file = "/tmp/test_nats_token_file_priority.txt";
        tokio::fs::write(token_file, "from_file").await.unwrap();

        let _token = EnvGuard::set(env_keys::NATS_TOKEN, "from_inline");
        let _token_file = EnvGuard::set(env_keys::NATS_TOKEN_FILE, token_file);

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.token, Some("from_inline".to_string()));

        let _ = tokio::fs::remove_file(token_file).await;
    }

    #[tokio::test]
    async fn test_from_env_password_from_file() {
        let pass_file = "/tmp/test_nats_password_file.txt";
        tokio::fs::write(pass_file, "secret_password").await.unwrap();

        let _user = EnvGuard::set(env_keys::NATS_USER, "alice");
        let _pass_file = EnvGuard::set(env_keys::NATS_PASSWORD_FILE, pass_file);

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.username, Some("alice".to_string()));
        assert_eq!(opts.auth.password, Some("secret_password".to_string()));

        let _ = tokio::fs::remove_file(pass_file).await;
    }

    #[tokio::test]
    async fn test_from_env_password_inline_priority_over_file() {
        let pass_file = "/tmp/test_nats_password_priority.txt";
        tokio::fs::write(pass_file, "from_file").await.unwrap();

        let _user = EnvGuard::set(env_keys::NATS_USER, "alice");
        let _pass = EnvGuard::set(env_keys::NATS_PASSWORD, "from_inline");
        let _pass_file = EnvGuard::set(env_keys::NATS_PASSWORD_FILE, pass_file);

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.username, Some("alice".to_string()));
        assert_eq!(opts.auth.password, Some("from_inline".to_string()));

        let _ = tokio::fs::remove_file(pass_file).await;
    }

    #[tokio::test]
    async fn test_from_env_file_with_whitespace_trimmed() {
        let token_file = "/tmp/test_nats_token_whitespace.txt";
        tokio::fs::write(token_file, "  token_value  \n").await.unwrap();

        let _token_file = EnvGuard::set(env_keys::NATS_TOKEN_FILE, token_file);

        let opts = ConnectOptions::new().from_env().await.unwrap();
        assert_eq!(opts.auth.token, Some("token_value".to_string()));

        let _ = tokio::fs::remove_file(token_file).await;
    }

    #[tokio::test]
    async fn test_from_env_missing_file_error() {
        let _token_file = EnvGuard::set(env_keys::NATS_TOKEN_FILE, "/nonexistent/path/token.txt");

        let result = ConnectOptions::new().from_env().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reading"));
    }
}
