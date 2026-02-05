//! # Example
//!
//! Using `SecretRef` to load secrets from configuration without embedding
//! secret values directly.
//!
//! ```ignore
//! use secret_ref::{SecretRef, SecretPolicy};
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize)]
//! struct Config {
//!     database_password: SecretRef,
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Example configuration (JSON / YAML / TOML all work)
//!     let cfg: Config = serde_json::from_str(r#"
//!         {
//!             "database_password": "env://DATABASE_PASSWORD"
//!         }
//!     "#)?;
//!
//!     // Resolve the secret under an explicit policy
//!     let policy = SecretPolicy::default();
//!     let secret = cfg.database_password.fetch(policy).await?;
//!
//!     // Use the secret value explicitly
//!     let password: &str = secret.expose();
//!     println!("Loaded database password ({} bytes)", password.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! The secret value is never serialized, logged, or embedded in configuration.
//! Only the reference is stored and transported.
#![deny(missing_docs)]
use serde_derive::{Deserialize};
use std::path::PathBuf;
use std::fmt;
use serde::ser::{Serialize, Serializer};
use std::path::Path;
use std::str::FromStr;

impl Serialize for SecretRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Tell serde to serialize it as a string
        serializer.collect_str(&self.to_string())
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretRef::Env(key) => {
                write!(f, "env://{}", key)
            }
            SecretRef::File(path) => {
                write!(f, "file://{}", path.display())
            }
            SecretRef::Http(url) => {
                write!(f, "{}", url)
            }
            
        }
    }
}

/// a wrapper struct around a secret value to encourage access to be explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    /// get the valueof the underlying secret.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// an error that occurs when fetching a ref fails.
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("environment variable not set: {0}")]
    MissingEnv(String),

    #[error("failed to read secret file {path}: {source}")]
    File {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("http secret fetch failed: {0}")]
    Http(String),
}

/// error that occurs when parsing a ref string fails.
#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum RefParseError {
    #[error("url parse error: {0}")]
    UrlErr(#[from] url::ParseError),
    #[error("unsupported schema")]
    UnsupportedSchema(String),
    #[error("missing ident for schema: {0}")]
    MissingIdent(String),
    #[error("failed to convert url to path: {0}")]
    UrlToPathFailed(String),
}

/// ```no_run
/// use secret_ref::{SecretRef, SecretPolicy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let secret = SecretRef::from("https://secrets.example.com/api-key");
///
/// let policy = SecretPolicy {
///     allow_http: true,
///     ..Default::default()
/// };
///
/// let value = secret.fetch(policy).await?;
/// println!("Loaded secret ({} bytes)", value.expose().len());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SecretPolicy {
    /// allow loading from env vars
    pub allow_env: bool,
    /// allow loading from files
    pub allow_file: bool,
    /// allow loading from http(s)
    pub allow_http: bool,
}

impl Default for SecretPolicy {
    fn default() -> Self {
        Self {
            allow_env: true,
            allow_file: true,
            allow_http: false,   // opt-in
        }
    }
}

/// A reference to a secret location.
///
/// # Example
///
/// ```no_run
/// use secret_ref::{SecretRef, SecretPolicy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let secret = SecretRef::from("env://API_TOKEN");
///
/// let policy = SecretPolicy::default();
/// let value = secret.fetch(policy).await?;
///
/// assert!(!value.expose().is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(try_from = "SecretRefInput")] // keep your existing Deserialize
pub enum SecretRef {
    /// secret from env var
    Env(String),
    /// secret from path
    File(PathBuf),
    /// secret from http(s) url.
    Http(url::Url),
}

impl<T: AsRef<Path>> From<T> for SecretRef {
    fn from(path: T) -> Self {
        Self::File(path.as_ref().to_path_buf())
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SecretRefInput {
    Url(String),
    Structured {
        scheme: String,
        value: String,
    },
}

impl TryFrom<SecretRefInput> for SecretRef {
    type Error = RefParseError;

    fn try_from(input: SecretRefInput) -> Result<Self, Self::Error> {
        match input {
            SecretRefInput::Url(s) => parse_secret_url(&s),
            SecretRefInput::Structured { scheme, value } => {
                match scheme.as_str() {
                    "env" => Ok(SecretRef::Env(value)),
                    "file" => Ok(SecretRef::File(PathBuf::from(value))),
                    "http" | "https" => {
                        let url = url::Url::parse(&format!("{scheme}://{value}"))?;
                        Ok(SecretRef::Http(url))
                    }
                    other => Err(RefParseError::UnsupportedSchema(other.into())),
                }
            }
        }
    }
}

fn parse_secret_url(s: &str) -> Result<SecretRef, RefParseError> {
    let url = url::Url::parse(s)?;

    match url.scheme() {
        "env" => {
            let key = url.host_str()
                .or_else(|| Some(url.path().trim_start_matches('/')))
                .filter(|s| !s.is_empty())
                .ok_or(RefParseError::MissingIdent("env://".into()))?;

            Ok(SecretRef::Env(key.to_string()))
        }
        "file" => Ok(SecretRef::File(
            PathBuf::from(url.to_file_path().map_err(|_e| RefParseError::UrlToPathFailed(url.to_string()))?)
        )),
        "http" | "https" => Ok(SecretRef::Http(url)),
        other => Err(RefParseError::UnsupportedSchema(other.to_string())),
    }
}

impl FromStr for SecretRef {
    type Err = RefParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_secret_url(s)
    }
}

impl SecretRef {
    /// fetches the secret associated with this reference using the supplied [`SecretPolicy`]
    pub async fn fetch(
        &self,
        policy: SecretPolicy,
    ) -> Result<SecretValue, SecretError> {
        match self {
            SecretRef::Env(key) => {
                if !policy.allow_env {
                    return Err(SecretError::MissingEnv(key.clone()));
                }

                std::env::var(key)
                    .map(SecretValue)
                    .map_err(|_| SecretError::MissingEnv(key.clone()))
            }

            SecretRef::File(path) => {
                if !policy.allow_file {
                    return Err(SecretError::File {
                        path: path.clone(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "file secrets disabled",
                        ),
                    });
                }

                let contents = tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| SecretError::File {
                        path: path.clone(),
                        source: e,
                    })?;

                Ok(SecretValue(contents.trim_end().to_string()))
            }

            SecretRef::Http(url) => {
                if !policy.allow_http {
                    return Err(SecretError::Http(
                        "http secrets are disabled by policy".into(),
                    ));
                }

                let resp = reqwest::get(url.clone())
                    .await
                    .map_err(|e| SecretError::Http(e.to_string()))?;

                if !resp.status().is_success() {
                    return Err(SecretError::Http(format!(
                        "http error: {}",
                        resp.status()
                    )));
                }

                let body = resp.text()
                    .await
                    .map_err(|e| SecretError::Http(e.to_string()))?;

                Ok(SecretValue(body.trim_end().to_string()))
            }
            
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Wrapper {
        secret: SecretRef,
    }

    /* -----------------------------
     * URL-style parsing
     * ----------------------------- */

    #[test]
    fn parse_env_url() {
        let cfg: Wrapper = serde_json::from_str(
            r#"{ "secret": "env://DATABASE_PASSWORD" }"#
        ).unwrap();

        assert_eq!(
            cfg.secret,
            SecretRef::Env("DATABASE_PASSWORD".into())
        );
    }

    #[test]
    fn parse_file_url() {
        let cfg: Wrapper = serde_json::from_str(
            r#"{ "secret": "file:///run/secrets/db_pass" }"#
        ).unwrap();

        assert_eq!(
            cfg.secret,
            SecretRef::File(PathBuf::from("/run/secrets/db_pass"))
        );
    }

    #[test]
    fn parse_http_url() {
        let cfg: Wrapper = serde_json::from_str(
            r#"{ "secret": "https://secrets.example.com/db" }"#
        ).unwrap();

        match cfg.secret {
            SecretRef::Http(url) => {
                assert_eq!(url.as_str(), "https://secrets.example.com/db");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /* -----------------------------
     * Structured parsing
     * ----------------------------- */

    #[test]
    fn parse_structured_env() {
        let cfg: Wrapper = serde_json::from_str(
            r#"
            {
              "secret": {
                "scheme": "env",
                "value": "API_TOKEN"
              }
            }
            "#
        ).unwrap();

        assert_eq!(
            cfg.secret,
            SecretRef::Env("API_TOKEN".into())
        );
    }

    #[test]
    fn parse_structured_file() {
        let cfg: Wrapper = serde_json::from_str(
            r#"
            {
              "secret": {
                "scheme": "file",
                "value": "/etc/secret.txt"
              }
            }
            "#
        ).unwrap();

        assert_eq!(
            cfg.secret,
            SecretRef::File(PathBuf::from("/etc/secret.txt"))
        );
    }

    /* -----------------------------
     * Format parity (JSON / YAML / TOML)
     * ----------------------------- */

    #[test]
    fn yaml_and_json_match() {
        let json_cfg: Wrapper = serde_json::from_str(
            r#"{ "secret": "env://FOO" }"#
        ).unwrap();

        let yaml_cfg: Wrapper = serde_yaml::from_str(
            r#"
            secret: env://FOO
            "#
        ).unwrap();

        assert_eq!(json_cfg.secret, yaml_cfg.secret);
    }

    #[test]
    fn toml_parsing() {
        let toml_cfg: Wrapper = toml::from_str(
            r#"
            secret = "env://BAR"
            "#
        ).unwrap();

        assert_eq!(
            toml_cfg.secret,
            SecretRef::Env("BAR".into())
        );
    }

    /* -----------------------------
     * Error cases
     * ----------------------------- */

    #[test]
    fn reject_unknown_scheme() {
        let err = serde_json::from_str::<Wrapper>(
            r#"{ "secret": "vault://foo" }"#
        ).unwrap_err();

    }

    #[test]
    fn reject_env_without_key() {
        let err = serde_json::from_str::<Wrapper>(
            r#"{ "secret": "env://" }"#
        ).unwrap_err();

    }

    #[test]
    fn reject_invalid_file_url() {
        let err = serde_json::from_str::<Wrapper>(
            r#"{ "secret": "file://relative/path" }"#
        ).unwrap_err();


    }

    /* -----------------------------
     * Round-trip sanity (optional)
     * ----------------------------- */

    #[test]
    fn http_round_trip_string() {
        let cfg: Wrapper = serde_json::from_str(
            r#"{ "secret": "https://example.com/secret" }"#
        ).unwrap();

        match cfg.secret {
            SecretRef::Http(url) => {
                assert_eq!(url.scheme(), "https");
                assert_eq!(url.host_str(), Some("example.com"));
            }
            _ => panic!("expected http secret"),
        }
    }
}