use color_eyre::eyre::Context;
use hickory_proto::dnssec::{Algorithm, crypto::RsaSigningKey};
use rustls_pki_types::{PrivateKeyDer, pem::PemObject};

/// Returns a Result with the validated RsaSigningKey.
/// We use String error here to avoid complex error-type mapping between build.rs and main.rs.
pub fn load_and_validate(key_material: &[u8]) -> color_eyre::Result<RsaSigningKey> {
    let key_der = PrivateKeyDer::from_pem_slice(key_material).context("Parsing private key PEM")?;
    RsaSigningKey::from_key_der(&key_der, Algorithm::RSASHA256)
        .context("Constructing RSA signing key")
}
