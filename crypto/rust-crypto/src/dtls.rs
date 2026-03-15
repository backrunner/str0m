//! DTLS implementation using dimpl with RustCrypto backend.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use str0m_proto::crypto::dtls::{DtlsCert, DtlsImplError, DtlsInstance, DtlsOutput, DtlsProvider};
use str0m_proto::crypto::CryptoError;

const DEFAULT_DTLS_MAX_QUEUE_RX: usize = 256;
const DEFAULT_DTLS_MAX_QUEUE_TX: usize = 64;

static DTLS_MAX_QUEUE_RX: AtomicUsize = AtomicUsize::new(DEFAULT_DTLS_MAX_QUEUE_RX);
static DTLS_MAX_QUEUE_TX: AtomicUsize = AtomicUsize::new(DEFAULT_DTLS_MAX_QUEUE_TX);

pub fn set_dtls_queue_limits(max_queue_rx: usize, max_queue_tx: usize) {
    DTLS_MAX_QUEUE_RX.store(max_queue_rx.max(1), Ordering::Relaxed);
    DTLS_MAX_QUEUE_TX.store(max_queue_tx.max(1), Ordering::Relaxed);
}

pub fn dtls_queue_limits() -> (usize, usize) {
    (
        DTLS_MAX_QUEUE_RX.load(Ordering::Relaxed),
        DTLS_MAX_QUEUE_TX.load(Ordering::Relaxed),
    )
}

// ============================================================================
// DTLS Provider Implementation
// ============================================================================

#[derive(Debug)]
pub(super) struct RustCryptoDtlsProvider;

impl DtlsProvider for RustCryptoDtlsProvider {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        // Use dimpl's rcgen-based certificate generation (with RustCrypto backend)
        dimpl::certificate::generate_self_signed_certificate()
            .ok()
            .map(|cert| DtlsCert {
                certificate: cert.certificate,
                private_key: cert.private_key,
            })
    }

    fn new_dtls(&self, cert: &DtlsCert) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        let dimpl_cert = dimpl::DtlsCertificate {
            certificate: cert.certificate.clone(),
            private_key: cert.private_key.clone(),
        };

        // Create a default dimpl Config with RustCrypto crypto provider
        let (max_queue_rx, max_queue_tx) = dtls_queue_limits();
        let mut builder = dimpl::Config::builder()
            .max_queue_rx(max_queue_rx)
            .max_queue_tx(max_queue_tx);
        if self.is_test() {
            // We need the DTLS impl to be deterministic for the BWE tests.
            builder = builder.dangerously_set_rng_seed(42);
        }

        let config = builder
            .build()
            .map_err(|e| CryptoError::Other(format!("dimpl config creation failed: {}", e)))?;

        let dtls = dimpl::Dtls::new(Arc::new(config), dimpl_cert);

        Ok(Box::new(RustCryptoDtlsInstance { dtls }))
    }
}

// ============================================================================
// DTLS Instance Wrapper
// ============================================================================

struct RustCryptoDtlsInstance {
    dtls: dimpl::Dtls,
}

impl std::fmt::Debug for RustCryptoDtlsInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustCryptoDtlsInstance").finish()
    }
}

impl DtlsInstance for RustCryptoDtlsInstance {
    fn set_active(&mut self, active: bool) {
        self.dtls.set_active(active);
    }

    fn handle_packet(&mut self, packet: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.handle_packet(packet)
    }

    fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> DtlsOutput<'a> {
        self.dtls.poll_output(buf)
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), DtlsImplError> {
        self.dtls.handle_timeout(now)
    }

    fn send_application_data(&mut self, data: &[u8]) -> Result<(), DtlsImplError> {
        self.dtls.send_application_data(data)
    }

    fn is_active(&self) -> bool {
        self.dtls.is_active()
    }
}
