// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! OpenSSL FIPS signature verification for `jsonwebtoken`.
//!
//! `jsonwebtoken` keeps parsing, key selection and claim validation; this
//! module supplies the process-wide crypto provider it calls for signatures,
//! digests and key components. Digests are fetched with `fips=yes`. The
//! `openssl` crate passes no property query to signature operations, so they
//! use the process default, and [`ensure_provider`] refuses to install unless
//! that default reaches only the FIPS provider.

use std::cell::RefCell;
use std::sync::OnceLock;

use jsonwebtoken::crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils};
use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::jwk::{EllipticCurve, ThumbprintHash};
use jsonwebtoken::signature::Verifier;
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, DecodingKeyKind, EncodingKey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::md::{Md, MdRef};
use openssl::md_ctx::MdCtx;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::RsaPssSaltlen;
use praxis_policy_core::CryptoError;
use praxis_policy_core::error::PluginError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Signature algorithms accepted under `jwt-openssl-fips`.
pub(crate) const APPROVED_ALGORITHMS: [Algorithm; 8] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

const MIN_RSA_BITS: u32 = 2048;

/// Matches the AWS-LC path, which refuses larger moduli.
const MAX_RSA_BITS: u32 = 8192;

/// The RFC 7515 Appendix A.2 example modulus, used only to probe that RSA
/// verification can be initialized.
const PROBE_RSA_MODULUS_HEX: &str = "A1F8160AE2E3C9B465CE8D2D656263362B927DBE29E1F02477FC1625CC90A136E38BD93497C5B6EA63DD7711E67C7429F956B0FB8A8F089ADC4B69893CC1333F53EDD019B87784252FEC914FE4857769594BEA4280D32C0F55BF62944F130396BC6E9BDF6EBDD2BDA3678EECA0C668F701B38DBFFB38C8342CE2FE6D27FADE4A5A4874979DD4B9CF9ADEC4C75B05852C2C0F5EF8A5C1750392F944E8ED64C110C6B647609AA4783AEB9C6C9AD755313050638B83665C6F6F7A82A396702A1F641B82D3EBF2392219491FB686872C5716F50AF8358D9A8B9D17C340728F7F87D89A18D8FCAB67AD84590C2ECF759339363C07034D6F606F9E21E05456CAE5E9A1";

/// The provider installed for `jsonwebtoken`. Signing is unsupported.
static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: new_signer,
    verifier_factory: new_verifier,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: rsa_components_from_private_key,
        rsa_pub_components_from_public_key: rsa_components_from_public_key,
        ec_pub_components_from_private_key: ec_components_from_private_key,
        ed_pub_components_from_private_key: ed_components_from_private_key,
        compute_digest,
    },
};

// -----------------------------------------------------------------------------
// Startup
// -----------------------------------------------------------------------------

/// Make this module's provider the active `jsonwebtoken` provider, or fail
/// with the reason and a `policy_crypto_failure` alarm.
///
/// Fails when the shared backend is unavailable, when OpenSSL's defaults reach
/// a non-FIPS provider, or when another provider is already active, including
/// the fallback `jsonwebtoken` selects if it is used before this call.
pub(crate) fn ensure_provider() -> Result<(), Box<PluginError>> {
    provider_ready().map_err(|source| startup_failure("jwt_provider", source))
}

/// [`ensure_provider`] without the alarm. A missing FIPS provider is checked
/// again on each call, so one loaded later is picked up.
pub(crate) fn provider_ready() -> Result<(), CryptoError> {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    if let Some(&ours) = INSTALLED.get() {
        return if ours {
            Ok(())
        } else {
            Err(CryptoError::ProviderConflict)
        };
    }
    praxis_policy_core::validate_crypto_backend()?;
    praxis_policy_core::crypto::require_fips_default()?;
    // A refused install returns the provider passed in, not the one already
    // installed, so only our own successful install proves ours is active.
    let ours = *INSTALLED.get_or_init(|| PROVIDER.install_default().is_ok());
    if ours {
        Ok(())
    } else {
        Err(CryptoError::ProviderConflict)
    }
}

/// Check that OpenSSL can initialize verification for each algorithm.
pub(crate) fn probe_algorithms(algorithms: &[Algorithm]) -> Result<(), Box<PluginError>> {
    for &algorithm in algorithms {
        probe(algorithm).map_err(|source| startup_failure("jwt_algorithm_probe", source))?;
    }
    Ok(())
}

/// Refuse an algorithm list containing one outside [`APPROVED_ALGORITHMS`].
pub(crate) fn check_algorithms(
    issuer: &str,
    field: &str,
    algorithms: &[Algorithm],
) -> Result<(), String> {
    match algorithms.iter().find(|a| !APPROVED_ALGORITHMS.contains(a)) {
        None => Ok(()),
        Some(alg) => Err(format!(
            "trusted_issuer '{issuer}': {field} lists {alg:?}, which jwt-openssl-fips does not \
             support; use one of {APPROVED_ALGORITHMS:?}"
        )),
    }
}

/// Refuse a key that FIPS verification would not accept.
///
/// RSA moduli must be 2048 to 8192 bits and EC keys on P-256 or P-384. Ed and
/// HMAC keys are refused.
pub(crate) fn check_key(key: &DecodingKey) -> Result<(), String> {
    match key.family() {
        AlgorithmFamily::Rsa => rsa_public_key(key).map(drop).map_err(|e| e.to_string()),
        AlgorithmFamily::Ec => ec_public_key(key).map(drop).map_err(|_unsupported| {
            "EC keys must be valid points on P-256 or P-384 with jwt-openssl-fips".to_owned()
        }),
        AlgorithmFamily::Ed => Err("Ed25519 keys are not supported with jwt-openssl-fips".into()),
        AlgorithmFamily::Hmac => {
            Err("shared-secret (HMAC) keys are not supported with jwt-openssl-fips".into())
        },
    }
}

fn startup_failure(op: &'static str, source: CryptoError) -> Box<PluginError> {
    tracing::error!(
        alarm = "policy_crypto_failure",
        op,
        error = %source,
        "JWT OpenSSL FIPS startup check failed"
    );
    Box::new(PluginError::Crypto { source })
}

/// Build a public key for `algorithm` and initialize verification with it.
///
/// Only called for [`APPROVED_ALGORITHMS`], which config validation enforces.
fn probe(algorithm: Algorithm) -> Result<(), CryptoError> {
    let key = if let Some(curve) = curve_nid(algorithm) {
        let group = EcGroup::from_curve_name(curve)?;
        let point = group
            .generator_opt()
            .ok_or(CryptoError::DigestLength)?
            .to_owned(&group)?;
        PKey::from_ec_key(EcKey::from_public_key(&group, &point)?)?
    } else {
        let n = BigNum::from_hex_str(PROBE_RSA_MODULUS_HEX)?;
        PKey::from_rsa(Rsa::from_public_components(n, BigNum::from_u32(65_537)?)?)?
    };
    init_verify(algorithm, &key)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Verification
// -----------------------------------------------------------------------------

/// A verifier whose OpenSSL context was initialized by the factory, so a
/// provider failure surfaces as [`ErrorKind::Provider`] rather than as an
/// invalid signature.
struct OpenSslVerifier {
    algorithm: Algorithm,
    context: RefCell<Option<MdCtx>>,
}

impl Verifier<Vec<u8>> for OpenSslVerifier {
    fn verify(
        &self,
        msg: &[u8],
        signature: &Vec<u8>,
    ) -> Result<(), jsonwebtoken::signature::Error> {
        let mut context = self
            .context
            .borrow_mut()
            .take()
            .ok_or_else(jsonwebtoken::signature::Error::new)?;
        let der;
        let signature = match ecdsa_coordinate_len(self.algorithm) {
            Some(len) => {
                der = ecdsa_der(signature, len).ok_or_else(jsonwebtoken::signature::Error::new)?;
                der.as_slice()
            },
            None => signature.as_slice(),
        };
        match context.digest_verify(msg, signature) {
            Ok(true) => Ok(()),
            _ => Err(jsonwebtoken::signature::Error::new()),
        }
    }
}

impl JwtVerifier for OpenSslVerifier {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>, Error> {
    let algorithm = *algorithm;
    if !APPROVED_ALGORITHMS.contains(&algorithm) {
        return Err(ErrorKind::InvalidAlgorithm.into());
    }
    if key.family() != algorithm.family() {
        return Err(ErrorKind::InvalidKeyFormat.into());
    }
    let public = match algorithm.family() {
        AlgorithmFamily::Ec => {
            let (curve, key) = ec_public_key(key)?;
            if Some(curve) != curve_nid(algorithm) {
                return Err(ErrorKind::InvalidEcdsaKey.into());
            }
            key
        },
        _ => rsa_public_key(key)?,
    };
    let context = init_verify(algorithm, &public).map_err(provider_error)?;
    Ok(Box::new(OpenSslVerifier {
        algorithm,
        context: RefCell::new(Some(context)),
    }))
}

fn new_signer(_: &Algorithm, _: &EncodingKey) -> Result<Box<dyn JwtSigner>, Error> {
    Err(ErrorKind::Provider("signing is not supported with jwt-openssl-fips".into()).into())
}

/// Initialize verification, selecting the FIPS digest and the JOSE padding.
fn init_verify(algorithm: Algorithm, key: &PKey<Public>) -> Result<MdCtx, CryptoError> {
    let digest = fips_digest(digest_name(algorithm))?;
    let mut context = MdCtx::new()?;
    let pkey = context.digest_verify_init(Some(digest), key)?;
    if algorithm.family() == AlgorithmFamily::Rsa {
        if matches!(
            algorithm,
            Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512
        ) {
            pkey.set_rsa_padding(Padding::PKCS1_PSS)?;
            pkey.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            pkey.set_rsa_mgf1_md(digest)?;
        } else {
            pkey.set_rsa_padding(Padding::PKCS1)?;
        }
    }
    Ok(context)
}

/// A JOSE `r || s` signature as DER, or `None` when its length is wrong.
fn ecdsa_der(signature: &[u8], coordinate_len: usize) -> Option<Vec<u8>> {
    if signature.len() != coordinate_len * 2 {
        return None;
    }
    let (r, s) = signature.split_at_checked(coordinate_len)?;
    let r = BigNum::from_slice(r).ok()?;
    let s = BigNum::from_slice(s).ok()?;
    EcdsaSig::from_private_components(r, s).ok()?.to_der().ok()
}

// -----------------------------------------------------------------------------
// Key Utilities
// -----------------------------------------------------------------------------

fn rsa_public_key(key: &DecodingKey) -> Result<PKey<Public>, Error> {
    let rsa = match key.kind() {
        DecodingKeyKind::SecretOrDer(der) => Rsa::public_key_from_der_pkcs1(der),
        DecodingKeyKind::RsaModulusExponent { n, e } => BigNum::from_slice(n)
            .and_then(|n| Ok((n, BigNum::from_slice(e)?)))
            .and_then(|(n, e)| Rsa::from_public_components(n, e)),
    }
    .map_err(|_parse| ErrorKind::InvalidRsaKey("not an RSA public key".into()))?;
    let bits = rsa.n().num_bits().unsigned_abs();
    if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
        return Err(ErrorKind::InvalidRsaKey(format!(
            "a {bits}-bit RSA key is outside the {MIN_RSA_BITS} to {MAX_RSA_BITS} bits \
             jwt-openssl-fips accepts"
        ))
        .into());
    }
    PKey::from_rsa(rsa).map_err(|e| provider_error(e.into()))
}

/// An EC public key from its uncompressed point, with the curve it is on.
fn ec_public_key(key: &DecodingKey) -> Result<(Nid, PKey<Public>), Error> {
    let point = key.try_get_as_bytes()?;
    let curve = match point.len() {
        65 => Nid::X9_62_PRIME256V1,
        97 => Nid::SECP384R1,
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };
    let ec = EcGroup::from_curve_name(curve)
        .and_then(|group| {
            let mut ctx = BigNumContext::new()?;
            let point = EcPoint::from_bytes(&group, point, &mut ctx)?;
            let ec = EcKey::from_public_key(&group, &point)?;
            ec.check_key()?;
            Ok(ec)
        })
        .map_err(|_parse| ErrorKind::InvalidEcdsaKey)?;
    Ok((
        curve,
        PKey::from_ec_key(ec).map_err(|e| provider_error(e.into()))?,
    ))
}

fn rsa_components_from_private_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let rsa = Rsa::private_key_from_der(der)
        .map_err(|_parse| ErrorKind::InvalidRsaKey("not an RSA private key".into()))?;
    Ok((rsa.n().to_vec(), rsa.e().to_vec()))
}

fn rsa_components_from_public_key(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let rsa = Rsa::public_key_from_der_pkcs1(der)
        .map_err(|_parse| ErrorKind::InvalidRsaKey("not an RSA public key".into()))?;
    Ok((rsa.n().to_vec(), rsa.e().to_vec()))
}

fn ec_components_from_private_key(
    der: &[u8],
    algorithm: Algorithm,
) -> Result<(EllipticCurve, Vec<u8>, Vec<u8>), Error> {
    let (curve, len) = match algorithm {
        Algorithm::ES256 => (EllipticCurve::P256, 32),
        Algorithm::ES384 => (EllipticCurve::P384, 48),
        _ => return Err(ErrorKind::InvalidEcdsaKey.into()),
    };
    let point = PKey::private_key_from_pkcs8(der)
        .and_then(|key| key.ec_key())
        .and_then(|ec| {
            if ec.group().curve_name() != curve_nid(algorithm) {
                return Ok(None);
            }
            let mut ctx = BigNumContext::new()?;
            let bytes = ec.public_key().to_bytes(
                ec.group(),
                PointConversionForm::UNCOMPRESSED,
                &mut ctx,
            )?;
            Ok(Some(bytes))
        })
        .map_err(|_parse| ErrorKind::InvalidEcdsaKey)?
        .ok_or(ErrorKind::InvalidEcdsaKey)?;
    match point.split_first() {
        Some((4, coordinates)) if coordinates.len() == len * 2 => {
            let (x, y) = coordinates.split_at(len);
            Ok((curve, x.to_vec(), y.to_vec()))
        },
        _ => Err(ErrorKind::InvalidEcdsaKey.into()),
    }
}

fn ed_components_from_private_key(_: &[u8], _: &EllipticCurve) -> Result<Vec<u8>, Error> {
    Err(ErrorKind::InvalidEddsaKey.into())
}

fn compute_digest(data: &[u8], hash: ThumbprintHash) -> Result<Vec<u8>, Error> {
    let name = match hash {
        ThumbprintHash::SHA256 => "SHA256",
        ThumbprintHash::SHA384 => "SHA384",
        ThumbprintHash::SHA512 => "SHA512",
        _ => return Err(ErrorKind::UnsupportedAlgorithm.into()),
    };
    let digest = fips_digest(name).map_err(provider_error)?;
    let digest_bytes = || -> Result<Vec<u8>, openssl::error::ErrorStack> {
        let mut context = MdCtx::new()?;
        context.digest_init(digest)?;
        context.digest_update(data)?;
        let mut out = vec![0_u8; digest.size()];
        context.digest_final(&mut out)?;
        Ok(out)
    };
    digest_bytes().map_err(|e| provider_error(e.into()))
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

fn digest_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::RS384 | Algorithm::PS384 | Algorithm::ES384 => "SHA384",
        Algorithm::RS512 | Algorithm::PS512 => "SHA512",
        _ => "SHA256",
    }
}

fn curve_nid(algorithm: Algorithm) -> Option<Nid> {
    match algorithm {
        Algorithm::ES256 => Some(Nid::X9_62_PRIME256V1),
        Algorithm::ES384 => Some(Nid::SECP384R1),
        _ => None,
    }
}

fn ecdsa_coordinate_len(algorithm: Algorithm) -> Option<usize> {
    match algorithm {
        Algorithm::ES256 => Some(32),
        Algorithm::ES384 => Some(48),
        _ => None,
    }
}

/// A digest fetched with `fips=yes`, cached once fetched.
fn fips_digest(name: &'static str) -> Result<&'static MdRef, CryptoError> {
    static SHA256: OnceLock<Md> = OnceLock::new();
    static SHA384: OnceLock<Md> = OnceLock::new();
    static SHA512: OnceLock<Md> = OnceLock::new();
    let slot = match name {
        "SHA384" => &SHA384,
        "SHA512" => &SHA512,
        _ => &SHA256,
    };
    if let Some(digest) = slot.get() {
        return Ok(digest);
    }
    let fetched = Md::fetch(None, name, Some("fips=yes"))?;
    Ok(slot.get_or_init(|| fetched))
}

fn provider_error(error: CryptoError) -> Error {
    ErrorKind::Provider(error.to_string()).into()
}
