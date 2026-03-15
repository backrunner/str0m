use str0m_proto::crypto as provider;

pub use provider::{AeadAes128Gcm, AeadAes128GcmCipher, AeadAes256Gcm, AeadAes256GcmCipher};
pub use provider::{Aes128CmSha1_80, Aes128CmSha1_80Cipher, CryptoProvider, CryptoSafe};
pub use provider::{Sha1HmacProvider, Sha256Provider};
pub use provider::{SrtpProvider, SupportedAeadAes128Gcm};
pub use provider::{SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};

/// DTLS related types and traits.
pub mod dtls {
    pub use super::provider::dtls::{DtlsInstance, DtlsProvider};

    pub use dimpl::DtlsCertificate as DtlsCert;
    pub use dimpl::KeyingMaterial;
    pub use dimpl::SrtpProfile;
    // Note: dimpl::Error is renamed to DtlsImplError to avoid conflict with str0m's DtlsError
    pub use dimpl::{Error as DtlsImplError, Output as DtlsOutput};
}

#[cfg(any(test, feature = "_internal_test_exports"))]
#[allow(unused)]
pub(crate) fn test_default_provider() -> &'static CryptoProvider {
    use std::sync::OnceLock;
    static TEST_PROVIDER: OnceLock<CryptoProvider> = OnceLock::new();
    TEST_PROVIDER.get_or_init(from_feature_flags)
}

/// Create a crypto provider based on enabled feature flags.
///
/// Priority order: aws-lc-rs, rust-crypto, openssl, wincrypto (Windows only)
///
/// Note: For Apple platforms, use the separate `str0m-apple-crypto` crate
/// and call `str0m_apple_crypto::default_provider()` directly.
#[allow(unreachable_code, clippy::needless_return)]
pub fn from_feature_flags() -> CryptoProvider {
    #[cfg(feature = "aws-lc-rs")]
    return str0m_aws_lc_rs::default_provider();

    #[cfg(feature = "rust-crypto")]
    return str0m_rust_crypto::default_provider();

    #[cfg(feature = "openssl")]
    return str0m_openssl::default_provider();

    #[cfg(all(feature = "apple-crypto", target_vendor = "apple"))]
    return str0m_apple_crypto::default_provider();

    #[cfg(all(feature = "wincrypto", target_os = "windows"))]
    return str0m_wincrypto::default_provider();

    panic!(
        "No crypto provider available. Enable one of: aws-lc-rs, 
             rust-crypto, openssl, wincrypto (Windows only), or use str0m-apple-crypto crate"
    );
}

/// Configure the DTLS implementation queue limits used for newly created peers.
///
/// The limits are applied by the active crypto backend when it constructs a new
/// DTLS instance. Values lower than 1 are clamped by the backend helpers.
#[allow(unreachable_code, clippy::needless_return)]
pub fn set_dtls_queue_limits(max_queue_rx: usize, max_queue_tx: usize) {
    #[cfg(feature = "aws-lc-rs")]
    return str0m_aws_lc_rs::set_dtls_queue_limits(max_queue_rx, max_queue_tx);

    #[cfg(feature = "rust-crypto")]
    return str0m_rust_crypto::set_dtls_queue_limits(max_queue_rx, max_queue_tx);

    let _ = (max_queue_rx, max_queue_tx);
}

/// Return the DTLS implementation queue limits that will be used for new peers.
#[allow(unreachable_code, clippy::needless_return)]
pub fn dtls_queue_limits() -> (usize, usize) {
    #[cfg(feature = "aws-lc-rs")]
    return str0m_aws_lc_rs::dtls_queue_limits();

    #[cfg(feature = "rust-crypto")]
    return str0m_rust_crypto::dtls_queue_limits();

    (256, 64)
}

mod finger;
pub use finger::Fingerprint;

pub use str0m_proto::crypto::{CryptoError, DtlsError};
