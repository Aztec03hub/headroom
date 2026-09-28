//! Extra trusted roots for upstream TLS.
//!
//! The upstream client trusts Mozilla's bundled roots plus the operating
//! system store (`rustls-tls-native-roots`), which is where IT installs a
//! corporate TLS-inspection root. Some deployments (containers, CI) have no
//! such store and hand the root over as a PEM file instead. These env vars
//! add it, matching the Python proxy's policy:
//!
//! * `HEADROOM_CA_BUNDLE` — Headroom's own knob.
//! * `NODE_EXTRA_CA_CERTS` — what Claude Code users already set.
//!
//! Both are additive. `SSL_CERT_FILE` / `SSL_CERT_DIR` are honored by
//! `rustls-native-certs` itself, as a replacement for the OS store.

use std::path::Path;

/// Env vars naming additive PEM bundles, in the order they are loaded.
pub const ADDITIVE_CA_VARS: [&str; 2] = ["HEADROOM_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"];

/// Root certificates from the additive env vars. Missing or unparsable
/// files are logged and skipped: a bad path must not take the proxy down.
pub fn extra_root_certificates() -> Vec<reqwest::Certificate> {
    extra_root_certificates_from(|var| std::env::var(var).ok())
}

fn extra_root_certificates_from(
    lookup: impl Fn(&str) -> Option<String>,
) -> Vec<reqwest::Certificate> {
    let mut certs = Vec::new();
    for var in ADDITIVE_CA_VARS {
        let Some(path) = lookup(var).filter(|p| !p.is_empty()) else {
            continue;
        };
        match load_pem_bundle(Path::new(&path)) {
            Ok(found) => {
                tracing::info!(
                    event = "tls_ca_bundle_loaded",
                    env_var = var,
                    path = %path,
                    certificates = found.len(),
                    "loaded extra upstream root certificates"
                );
                certs.extend(found);
            }
            Err(err) => {
                tracing::warn!(
                    event = "tls_ca_bundle_skipped",
                    env_var = var,
                    path = %path,
                    error = %err,
                    "could not load extra root certificates; skipping"
                );
            }
        }
    }
    certs
}

fn load_pem_bundle(path: &Path) -> Result<Vec<reqwest::Certificate>, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let certs = reqwest::Certificate::from_pem_bundle(&bytes).map_err(|e| e.to_string())?;
    if certs.is_empty() {
        return Err("no PEM certificates found".to_string());
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway self-signed CA, only parsed here, never used for a handshake.
    const TEST_CA: &str = "-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIUQJOjUYts91bSLsemwb5EuzdkOnMwCgYIKoZIzj0EAwIw
MjEVMBMGA1UECgwMWnNjYWxlciBJbmMuMRkwFwYDVQQDDBBIZWFkcm9vbSBUZXN0
IENBMB4XDTI2MDkyODE0MjM1MloXDTM2MDkyNTE0MjM1MlowMjEVMBMGA1UECgwM
WnNjYWxlciBJbmMuMRkwFwYDVQQDDBBIZWFkcm9vbSBUZXN0IENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEKZ0h9e4jj/eJiBVh4eMZ3d+pcugxj/hEhqzoAo9r
+7KL4dGgqrg2GH4IP6sfKNdssKHshDcjz+HWiKVGyCx08KNTMFEwHQYDVR0OBBYE
FPFmGy3B6aRYxGMB1P/up4Y05PxbMB8GA1UdIwQYMBaAFPFmGy3B6aRYxGMB1P/u
p4Y05PxbMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgZTHC/ZR0
SI8i1dYBBaT8a2e/CVF6MmgXObYWEg2YYk8CIQC8e2+jUZDkYV+Ct3y0JQO7OSfp
+Yyjbym7JFsfsp4fVQ==
-----END CERTIFICATE-----
";

    #[test]
    fn unset_and_empty_vars_add_nothing() {
        assert!(extra_root_certificates_from(|_| None).is_empty());
        assert!(extra_root_certificates_from(|_| Some(String::new())).is_empty());
    }

    #[test]
    fn missing_file_is_skipped() {
        let certs = extra_root_certificates_from(|var| {
            (var == "HEADROOM_CA_BUNDLE").then(|| "/nonexistent/headroom-ca.pem".to_string())
        });
        assert!(certs.is_empty());
    }

    #[test]
    fn non_pem_file_is_skipped() {
        let dir = std::env::temp_dir().join(format!("headroom-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not-a-cert.pem");
        std::fs::write(&path, "hello").unwrap();
        let p = path.display().to_string();
        let certs =
            extra_root_certificates_from(|var| (var == "NODE_EXTRA_CA_CERTS").then(|| p.clone()));
        assert!(certs.is_empty());
    }

    #[test]
    fn both_additive_vars_are_loaded() {
        let dir = std::env::temp_dir().join(format!("headroom-tls-ok-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corp-root.pem");
        std::fs::write(&path, TEST_CA).unwrap();
        let p = path.display().to_string();
        let certs = extra_root_certificates_from(|_| Some(p.clone()));
        assert_eq!(certs.len(), ADDITIVE_CA_VARS.len());
    }
}
