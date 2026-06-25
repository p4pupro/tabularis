use crate::models::ConnectionParams;
use deadpool_postgres::{Manager as PgPoolManager, Pool as PgPool};
use once_cell::sync::Lazy;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, WebPkiServerVerifier};
use rustls::crypto::verify_tls12_signature;
use rustls::crypto::verify_tls13_signature;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct};
use rustls::{ClientConfig, Error as TlsError, RootCertStore};
use rustls_platform_verifier::BuilderVerifierExt;
use sqlx::{sqlite::SqliteConnectOptions, MySql, Pool, Sqlite};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_postgres::{config::SslMode as PgSslMode, Config as PgConfig};
use tokio_postgres_rustls::MakeRustlsConnect;

/// Walks `Error::source()` to surface the real cause, which `tokio_postgres`
/// hides behind a generic "error performing TLS handshake".
pub(crate) fn format_error_chain<E: std::error::Error + ?Sized>(err: &E) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        out.push_str(" -> ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

fn ensure_rustls_crypto_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

type PoolMap<T> = Arc<RwLock<HashMap<String, Pool<T>>>>;
type PgPoolMap = Arc<RwLock<HashMap<String, PgPool>>>;

static MYSQL_POOLS: Lazy<PoolMap<MySql>> = Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));
static POSTGRES_POOLS: Lazy<PgPoolMap> = Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));
static SQLITE_POOLS: Lazy<PoolMap<Sqlite>> = Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

const DEFAULT_MYSQL_CONNECT_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MYSQL_TIMEZONE: &str = "SYSTEM";

fn mysql_setting_value(key: &str) -> Option<serde_json::Value> {
    crate::config::get_cached_config()
        .plugins
        .and_then(|plugins| plugins.get("mysql").cloned())
        .and_then(|plugin| plugin.settings.get(key).cloned())
}

fn mysql_string_setting(key: &str, default: &str) -> String {
    mysql_setting_value(key)
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn mysql_numeric_setting(key: &str, default: u64) -> u64 {
    mysql_setting_value(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().and_then(|item| u64::try_from(item).ok()))
                .or_else(|| value.as_str().and_then(|item| item.parse::<u64>().ok()))
        })
        .unwrap_or(default)
}

/// Stable pool key: uses `connection_id` when present (saved connections),
/// else `host:port:database` (ad-hoc). The TLS/iam tuple is appended so
/// different SSL settings of the same connection get separate pools.
pub(crate) fn build_connection_key(
    params: &ConnectionParams,
    connection_id: Option<&str>,
) -> String {
    let tls_key = match params.driver.as_str() {
        "mysql" => Some(format!(
            "ssl:{}:{}:{}:{}:iam:{}",
            params.ssl_mode.as_deref().unwrap_or("default"),
            params.ssl_ca.as_deref().unwrap_or(""),
            params.ssl_cert.as_deref().unwrap_or(""),
            params.ssl_key.as_deref().unwrap_or(""),
            if params.use_iam_auth.unwrap_or(false) {
                "true"
            } else {
                "false"
            }
        )),
        "postgres" => {
            let ssl_mode = params.ssl_mode.as_deref().unwrap_or("prefer");
            let ssl_ca = match ssl_mode {
                "verify-ca" | "verify-full" => params.ssl_ca.as_deref().unwrap_or(""),
                _ => "",
            };
            Some(format!("ssl:{ssl_mode}:{ssl_ca}"))
        }
        _ => None,
    };

    let base_key = if let Some(conn_id) = connection_id {
        format!("{}:conn:{}:{}", params.driver, conn_id, params.database)
    } else {
        format!(
            "{}:{}:{}:{}",
            params.driver,
            params.host.as_deref().unwrap_or("localhost"),
            params.port.unwrap_or(0),
            params.database
        )
    };

    if let Some(tls_key) = tls_key {
        format!("{base_key}:{tls_key}")
    } else {
        base_key
    }
}

pub(crate) fn build_mysql_options(
    params: &ConnectionParams,
    override_db: Option<&str>,
) -> Result<sqlx::mysql::MySqlConnectOptions, String> {
    use sqlx::mysql::{MySqlConnectOptions, MySqlSslMode};

    let username = params.username.as_deref().unwrap_or_default();
    let password = params.password.as_deref().unwrap_or_default();
    let host = params.host.as_deref().unwrap_or("localhost");
    let port = params.port.unwrap_or(3306);
    let database = override_db.unwrap_or_else(|| params.database.primary());
    let timezone = mysql_string_setting("timezone", DEFAULT_MYSQL_TIMEZONE);

    // ssl_mode: user-selected, with auto-escalation to VerifyCa when an ssl_ca
    // is supplied under Required/Preferred. sqlx-mysql only forwards the CA
    // bundle to the TLS connector for VerifyCa/VerifyIdentity, so on macOS the
    // system keychain handles verification for the weaker modes and rejects
    // the regional RDS root CAs with an opaque handshake error.
    let has_user_ca = params
        .ssl_ca
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let mut ssl_mode = match params.ssl_mode.as_deref().unwrap_or("required") {
        "disabled" | "disable" => MySqlSslMode::Disabled,
        "preferred" | "prefer" => MySqlSslMode::Preferred,
        "required" | "require" => MySqlSslMode::Required,
        "verify_ca" => MySqlSslMode::VerifyCa,
        "verify_identity" => MySqlSslMode::VerifyIdentity,
        _ => MySqlSslMode::Required,
    };
    if has_user_ca
        && matches!(ssl_mode, MySqlSslMode::Required | MySqlSslMode::Preferred)
    {
        ssl_mode = MySqlSslMode::VerifyCa;
    }

    // AWS RDS IAM auth: `password` carries the pre-signed RDS auth token
    // (from `aws rds generate-db-auth-token`), sent cleartext via
    // mysql_clear_password over TLS. Refuse to send it unencrypted.
    if params.use_iam_auth.unwrap_or(false) {
        if matches!(ssl_mode, MySqlSslMode::Disabled) {
            return Err(
                "AWS IAM authentication requires a TLS/SSL mode to be enabled \
                 (Preferred, Required, Verify CA, or Verify Identity). Refusing \
                 to send the RDS auth token over an unencrypted connection."
                    .to_string(),
            );
        }
        // Saved connections get the token injected from the keychain after
        // this builder returns, so an empty password is fine for them.
        if password.is_empty() && params.connection_id.is_none() {
            return Err(
                "AWS IAM authentication is enabled but the password field is \
                 empty. Paste the output of `aws rds generate-db-auth-token` \
                 into the password field."
                    .to_string(),
            );
        }
    }

    log::info!(
        "build_mysql_options: driver=mysql host={host} port={port} \
         ssl_mode_param={:?} ssl_ca_present={} effective_ssl_mode={:?} \
         iam_auth={} password_len={}",
        params.ssl_mode,
        has_user_ca,
        ssl_mode,
        params.use_iam_auth.unwrap_or(false),
        password.len(),
    );

    let mut options = MySqlConnectOptions::new()
        .host(host)
        .port(port)
        .username(username)
        .database(database)
        .timezone(timezone)
        .ssl_mode(ssl_mode);

    // Skip `.password(...)` when the password is empty: an empty string is
    // stamped by sqlx as "user pressed Enter", which the server rejects with
    // "Access denied (using password: YES)". Saved IAM-auth connections get
    // the token injected from the keychain after this builder returns.
    if !password.is_empty() {
        options = options.password(password);
    }

    if let Some(ca) = &params.ssl_ca {
        options = options.ssl_ca(ca);
    }
    if let Some(cert) = &params.ssl_cert {
        options = options.ssl_client_cert(cert);
    }
    if let Some(key) = &params.ssl_key {
        options = options.ssl_client_key(key);
    }

    // IAM auth: the server announces `mysql_clear_password` and rejects the
    // handshake with "mysql_cleartext_plugin disabled" unless the client
    // opts in. Safe because the token only travels over the TLS link above.
    if params.use_iam_auth.unwrap_or(false) {
        options = options.enable_cleartext_plugin(true);
    }

    Ok(options)
}

pub(crate) fn build_postgres_configurations(params: &ConnectionParams) -> PgConfig {
    let mut cfg = PgConfig::new();
    cfg.user(params.username.as_deref().unwrap_or_default())
        .password(params.password.as_deref().unwrap_or_default())
        .port(params.port.unwrap_or(5432))
        .host(params.host.as_deref().unwrap_or_default())
        .dbname(&format!("{}", params.database));

    if let Some(ssl_mode) = params.ssl_mode.as_deref() {
        match ssl_mode {
            "disable" => {
                cfg.ssl_mode(PgSslMode::Disable);
            }
            // tokio_postgres does not have SslMode::Allow.
            // "allow" (try non-SSL first, fallback to SSL) requires application-level
            // logic that this codebase does not implement. For now, map to Prefer
            // which at least allows both SSL and non-SSL connections.
            "allow" => {
                cfg.ssl_mode(PgSslMode::Prefer);
            }
            "prefer" => {
                cfg.ssl_mode(PgSslMode::Prefer);
            }
            "require" | "verify-ca" | "verify-full" => {
                cfg.ssl_mode(PgSslMode::Require);
            }
            _ => {}
        };
    }

    cfg
}

/// Build the rustls connector for the PostgreSQL pool.
///
/// `rustls` (not `native-tls`) because macOS Secure Transport applies a
/// strict `id-kp-serverAuth` EKU check to user-supplied root anchors and
/// rejects valid CA certs. `ssl_ca` overrides the platform trust store —
/// RDS users point it at the AWS global bundle
/// (`https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem`).
/// The bundle is intentionally not vendored: AWS rotates these CAs every
/// 1-3 years, so distributors pull a fresh copy at packaging time.
///
/// SSL modes:
/// - `disable`: no TLS
/// - `allow`/`prefer`: TLS without certificate verification
/// - `require`: force TLS without certificate verification
///   (prior to v0.10.3 this validated the chain; it now matches libpq).
/// - `verify-ca`: force TLS, validate chain, skip hostname check
/// - `verify-full`: force TLS, validate chain and hostname
pub(crate) fn build_postgres_tls_connector(
    params: &ConnectionParams,
) -> Result<MakeRustlsConnect, String> {
    ensure_rustls_crypto_provider();
    let ssl_mode = params.ssl_mode.as_deref().unwrap_or("prefer");
    let user_ca = params.ssl_ca.as_deref().filter(|s| !s.trim().is_empty());

    let config = match ssl_mode {
        "disable" | "allow" | "prefer" => {
            // No cert verification; PgSslMode below controls whether TLS is attempted.
            let verifier = Arc::new(NoCertVerifier::new());
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        "require" => {
            // Force TLS, skip cert validation.
            let verifier = Arc::new(NoCertVerifier::new());
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        "verify-ca" => {
            // Validate chain, skip hostname. Requires an explicit CA file —
            // platform roots are not used (macOS EKU check rejects them).
            let ca_path = user_ca.ok_or_else(|| {
                "verify-ca mode requires an explicit CA file via the connection's \
                CA Certificate field. On macOS, platform root certificates are \
                not compatible with strict EKU checks. For automatic platform \
                trust, use verify-full instead."
                    .to_string()
            })?;
            let roots = load_roots_from_pem(ca_path)?;
            let verifier = Arc::new(VerifyCaCertVerifier::new(roots)?);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
        "verify-full" => {
            // Validate certificate chain AND hostname.
            if user_ca.is_none() {
                // Use platform verifier for full validation.
                ClientConfig::builder()
                    .with_platform_verifier()
                    .map_err(|e| format!("Failed to build platform TLS verifier: {}", e))?
                    .with_no_client_auth()
            } else {
                // Use custom CA with full hostname verification.
                let roots = load_roots_from_pem(user_ca.unwrap())?;
                let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
                    .build()
                    .map_err(|e| format!("Failed to build certificate verifier: {e}"))?;
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
        }
        _ => {
            // Unknown mode, fall back to no verification.
            let verifier = Arc::new(NoCertVerifier::new());
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        }
    };
    Ok(MakeRustlsConnect::new(config))
}

/// Load root certificates from a PEM file.
pub(crate) fn load_roots_from_pem(path: &str) -> Result<RootCertStore, String> {
    let pem =
        std::fs::read(path).map_err(|e| format!("Failed to read ssl_ca file '{}': {}", path, e))?;
    let mut roots = RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(&pem[..]);
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert.map_err(|e| format!("Failed to parse ssl_ca '{}': {}", path, e))?;
        roots
            .add(cert)
            .map_err(|e| format!("Failed to add ssl_ca cert from '{}': {}", path, e))?;
    }
    if roots.is_empty() {
        return Err(format!(
            "ssl_ca '{}' contained no PEM CERTIFICATE blocks",
            path
        ));
    }
    Ok(roots)
}

/// A certificate verifier that skips certificate validation entirely.
/// Used for sslmode=require, prefer, allow.
#[derive(Debug)]
struct NoCertVerifier {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl NoCertVerifier {
    fn new() -> Self {
        let provider = CryptoProvider::get_default()
            .expect("rustls CryptoProvider not installed");
        Self {
            supported: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// A certificate verifier that validates the certificate chain against
/// a custom root store but skips hostname verification.
/// Matches libpq `sslmode=verify-ca` behavior.
///
/// Uses `verify_server_cert_signed_by_trust_anchor` directly rather than
/// wrapping `WebPkiServerVerifier` — this makes the "skip hostname check"
/// intent explicit, avoids double-verifying the chain, and prevents the
/// fragile `.or(Ok(...))` error-recovery pattern.
#[derive(Debug)]
struct VerifyCaCertVerifier {
    roots: Arc<RootCertStore>,
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl VerifyCaCertVerifier {
    fn new(roots: RootCertStore) -> Result<Self, String> {
        if roots.is_empty() {
            return Err(
                "No root certificates available. For verify-ca mode, \
                you must specify an explicit CA file via the connection's \
                CA Certificate field. On macOS, the system keychain does \
                not provide root anchors compatible with strict EKU checks."
                    .to_string(),
            );
        }
        let provider = CryptoProvider::get_default()
            .ok_or("No rustls CryptoProvider installed")?;
        Ok(Self {
            roots: Arc::new(roots),
            supported: provider.signature_verification_algorithms,
        })
    }
}

impl ServerCertVerifier for VerifyCaCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Validate the certificate chain against our root store.
        // We intentionally skip hostname verification (verify-ca semantics).
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

fn build_sqlite_connectoptions(params: &ConnectionParams) -> SqliteConnectOptions {
    SqliteConnectOptions::new().filename(params.database.to_string())
}

pub async fn get_mysql_pool(params: &ConnectionParams) -> Result<Pool<MySql>, String> {
    let connection_id = params.connection_id.as_deref();
    get_mysql_pool_with_id(params, connection_id).await
}

pub async fn get_mysql_pool_with_id(
    params: &ConnectionParams,
    connection_id: Option<&str>,
) -> Result<Pool<MySql>, String> {
    get_mysql_pool_for_database_with_id(params, None, connection_id).await
}

pub async fn get_mysql_pool_for_database(
    params: &ConnectionParams,
    override_db: Option<&str>,
) -> Result<Pool<MySql>, String> {
    let connection_id = params.connection_id.as_deref();
    get_mysql_pool_for_database_with_id(params, override_db, connection_id).await
}

async fn get_mysql_pool_for_database_with_id(
    params: &ConnectionParams,
    override_db: Option<&str>,
    connection_id: Option<&str>,
) -> Result<Pool<MySql>, String> {
    let key = if let Some(db) = override_db {
        format!("{}:{}", build_connection_key(params, connection_id), db)
    } else {
        build_connection_key(params, connection_id)
    };

    // Try to get existing pool
    {
        let pools = MYSQL_POOLS.read().await;
        if let Some(pool) = pools.get(&key) {
            log::debug!(
                "Using existing MySQL connection pool for: {} (key: {})",
                override_db.unwrap_or_else(|| params.database.primary()),
                key
            );
            return Ok(pool.clone());
        }
    }

    // Create new pool
    log::info!(
        "Creating new MySQL connection pool for: {}@{:?} (key: {})",
        params.username.as_deref().unwrap_or("unknown"),
        params.host,
        key
    );
    // sqlx-mysql's rustls backend (selected when sqlx is built with
    // `tls-rustls` and not `tls-native-tls`) panics on the first handshake
    // unless a process-level `CryptoProvider` has been installed. We share
    // the same install-once helper the Postgres deadpool path uses.
    ensure_rustls_crypto_provider();
    let options = build_mysql_options(params, override_db)?;
    let connect_timeout = Duration::from_millis(mysql_numeric_setting(
        "connectTimeout",
        DEFAULT_MYSQL_CONNECT_TIMEOUT_MS,
    ));
    let pool = tokio::time::timeout(
        connect_timeout,
        sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(10)
            .connect_with(options),
    )
    .await
    .map_err(|_| {
        format!(
            "Timed out creating MySQL connection pool after {} ms",
            connect_timeout.as_millis()
        )
    })?
    .map_err(|e| {
        log::error!("Failed to create MySQL connection pool: {}", e);
        e.to_string()
    })?;

    log::info!(
        "MySQL connection pool created successfully for: {} (key: {})",
        override_db.unwrap_or_else(|| params.database.primary()),
        key
    );

    // Store pool
    {
        let mut pools = MYSQL_POOLS.write().await;
        pools.insert(key, pool.clone());
    }

    Ok(pool)
}

pub async fn get_postgres_pool(params: &ConnectionParams) -> Result<PgPool, String> {
    let connection_id = params.connection_id.as_deref();
    get_postgres_pool_with_id(params, connection_id).await
}

pub async fn get_postgres_pool_with_id(
    params: &ConnectionParams,
    connection_id: Option<&str>,
) -> Result<PgPool, String> {
    let key = build_connection_key(params, connection_id);

    // Try to get existing pool
    {
        let pools = POSTGRES_POOLS.read().await;
        if let Some(pool) = pools.get(&key) {
            log::debug!(
                "Using existing PostgreSQL connection pool for: {} (key: {})",
                params.database,
                key
            );
            return Ok(pool.clone());
        }
    }

    // Create new pool
    log::info!(
        "Creating new PostgreSQL connection pool for: {}@{:?} (key: {})",
        params.username.as_deref().unwrap_or("unknown"),
        params.host,
        key
    );

    let cfg = build_postgres_configurations(params);

    let tls_connector = build_postgres_tls_connector(params).map_err(|e| {
        log::error!("Failed to create TLS connector for PostgreSQL pool: {}", e);
        e
    })?;

    let pool = PgPool::builder(PgPoolManager::new(cfg, tls_connector))
        .max_size(10)
        .build()
        .map_err(|e| {
            let detail = format_error_chain(&e);
            log::error!("Failed to create PostgreSQL connection pool: {}", detail);
            detail
        })?;

    log::info!(
        "PostgreSQL connection pool created successfully for: {} (key: {})",
        params.database,
        key
    );

    // Store pool
    {
        let mut pools = POSTGRES_POOLS.write().await;
        pools.insert(key, pool.clone());
    }

    Ok(pool)
}

pub async fn get_sqlite_pool(params: &ConnectionParams) -> Result<Pool<Sqlite>, String> {
    let connection_id = params.connection_id.as_deref();
    get_sqlite_pool_with_id(params, connection_id).await
}

pub async fn get_sqlite_pool_with_id(
    params: &ConnectionParams,
    connection_id: Option<&str>,
) -> Result<Pool<Sqlite>, String> {
    let key = build_connection_key(params, connection_id);

    // Try to get existing pool
    {
        let pools = SQLITE_POOLS.read().await;
        if let Some(pool) = pools.get(&key) {
            log::debug!(
                "Using existing SQLite connection pool for: {} (key: {})",
                params.database,
                key
            );
            return Ok(pool.clone());
        }
    }

    // Create new pool
    log::info!(
        "Creating new SQLite connection pool for database: {} (key: {})",
        params.database,
        key
    );
    let options = build_sqlite_connectoptions(params);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5) // SQLite has lower concurrency needs
        .connect_with(options)
        .await
        .map_err(|e| {
            log::error!("Failed to create SQLite connection pool: {}", e);
            e.to_string()
        })?;

    log::info!(
        "SQLite connection pool created successfully for: {} (key: {})",
        params.database,
        key
    );

    // Store pool
    {
        let mut pools = SQLITE_POOLS.write().await;
        pools.insert(key, pool.clone());
    }

    Ok(pool)
}

/// Check whether a connection pool exists for the given params without creating one.
pub async fn has_pool(params: &ConnectionParams, connection_id: Option<&str>) -> bool {
    has_pool_for_database(params, None, connection_id).await
}

/// Check whether a connection pool exists for the given params and database without creating one.
pub async fn has_pool_for_database(
    params: &ConnectionParams,
    override_db: Option<&str>,
    connection_id: Option<&str>,
) -> bool {
    let key = if let Some(db) = override_db {
        format!("{}:{}", build_connection_key(params, connection_id), db)
    } else {
        build_connection_key(params, connection_id)
    };
    match params.driver.as_str() {
        "mysql" => MYSQL_POOLS.read().await.contains_key(&key),
        "postgres" => POSTGRES_POOLS.read().await.contains_key(&key),
        "sqlite" => SQLITE_POOLS.read().await.contains_key(&key),
        _ => false,
    }
}

/// Close a specific connection pool
pub async fn close_pool(params: &ConnectionParams) {
    let connection_id = params.connection_id.as_deref();
    close_pool_with_id(params, connection_id).await;
}

/// Close a specific connection pool by connection_id
pub async fn close_pool_with_id(params: &ConnectionParams, connection_id: Option<&str>) {
    let key = build_connection_key(params, connection_id);

    match params.driver.as_str() {
        "mysql" => {
            let mut pools = MYSQL_POOLS.write().await;
            if let Some(pool) = pools.remove(&key) {
                log::info!(
                    "Closing MySQL connection pool for: {} (key: {})",
                    params.database,
                    key
                );
                pool.close().await;
                log::info!(
                    "MySQL connection pool closed for: {} (key: {})",
                    params.database,
                    key
                );
            }
        }
        "postgres" => {
            let mut pools = POSTGRES_POOLS.write().await;
            if let Some(pool) = pools.remove(&key) {
                log::info!(
                    "Closing PostgreSQL connection pool for: {} (key: {})",
                    params.database,
                    key
                );
                pool.close();
                log::info!(
                    "PostgreSQL connection pool closed for: {} (key: {})",
                    params.database,
                    key
                );
            }
        }
        "sqlite" => {
            let mut pools = SQLITE_POOLS.write().await;
            if let Some(pool) = pools.remove(&key) {
                log::info!(
                    "Closing SQLite connection pool for: {} (key: {})",
                    params.database,
                    key
                );
                pool.close().await;
                log::info!(
                    "SQLite connection pool closed for: {} (key: {})",
                    params.database,
                    key
                );
            }
        }
        _ => {}
    }
}

/// Close all connection pools (useful on app shutdown)
pub async fn close_all_pools() {
    {
        let mut pools = MYSQL_POOLS.write().await;
        for (_, pool) in pools.drain() {
            pool.close().await;
        }
    }
    {
        let mut pools = POSTGRES_POOLS.write().await;
        for (_, pool) in pools.drain() {
            pool.close();
        }
    }
    {
        let mut pools = SQLITE_POOLS.write().await;
        for (_, pool) in pools.drain() {
            pool.close().await;
        }
    }
}
