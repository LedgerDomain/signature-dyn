use crate::{
    ED448_JOSE_ALGORITHM, ED25519_JOSE_ALGORITHM, Error, P256_JOSE_ALGORITHM, P384_JOSE_ALGORITHM,
    P521_JOSE_ALGORITHM, Result, SECP256K1_JOSE_ALGORITHM, bail,
};

/// An enum representing a subset of supported key types.
// NOTE: There are many missing key types, mostly because their private versions are missing from the multicodec table.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum KeyType {
    Ed25519,
    Ed448,
    P256,
    P384,
    P521,
    RSA,
    Secp256k1,
    Sr25519,
    X25519,
}

/// The list of KeyType variants.
pub const KEY_TYPE_V: &[KeyType] = &[
    KeyType::Ed25519,
    KeyType::Ed448,
    KeyType::P256,
    KeyType::P384,
    KeyType::P521,
    KeyType::RSA,
    KeyType::Secp256k1,
    KeyType::Sr25519,
    KeyType::X25519,
];

impl KeyType {
    /// Get the string representation of this key type.
    pub fn as_str(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "Ed25519",
            KeyType::Ed448 => "Ed448",
            KeyType::P256 => "P256",
            KeyType::P384 => "P384",
            KeyType::P521 => "P521",
            KeyType::RSA => "RSA",
            KeyType::Secp256k1 => "Secp256k1",
            KeyType::Sr25519 => "Sr25519",
            KeyType::X25519 => "X25519",
        }
    }
    /// Get the JOSE algorithm name for this key type (this assumes there's only one
    /// algorithm per key type, which isn't generally true, but will suffice for these
    /// KeyType variants).
    pub fn jose_algorithm(self) -> &'static str {
        match self {
            KeyType::Ed25519 => ED25519_JOSE_ALGORITHM,
            KeyType::Ed448 => ED448_JOSE_ALGORITHM,
            KeyType::P256 => P256_JOSE_ALGORITHM,
            KeyType::P384 => P384_JOSE_ALGORITHM,
            KeyType::P521 => P521_JOSE_ALGORITHM,
            // KeyType::RSA => RSA_JOSE_ALGORITHM,
            KeyType::Secp256k1 => SECP256K1_JOSE_ALGORITHM,
            // KeyType::Sr25519 => SR25519_JOSE_ALGORITHM,
            // KeyType::X25519 => X25519_JOSE_ALGORITHM,
            _ => {
                panic!("Unsupported key type: {:?}", self)
            }
        }
    }
    pub fn try_from_jose_algorithm(jose_algorithm: &'static str) -> Result<Self> {
        match jose_algorithm {
            ED25519_JOSE_ALGORITHM => Ok(KeyType::Ed25519),
            ED448_JOSE_ALGORITHM => Ok(KeyType::Ed448),
            P256_JOSE_ALGORITHM => Ok(KeyType::P256),
            P384_JOSE_ALGORITHM => Ok(KeyType::P384),
            P521_JOSE_ALGORITHM => Ok(KeyType::P521),
            SECP256K1_JOSE_ALGORITHM => Ok(KeyType::Secp256k1),
            _ => {
                bail!("Unsupported key type: {:?}", jose_algorithm)
            }
        }
    }
    /// Get the multicodec private key codec value for this key type.
    #[cfg(feature = "ssi-multicodec")]
    pub fn as_priv_key_codec(self) -> u64 {
        match self {
            KeyType::Ed25519 => ssi_multicodec::ED25519_PRIV,
            KeyType::Ed448 => {
                // Note that this codec was merged into multicodec in https://github.com/multiformats/multicodec/pull/390,
                // but ssi-multicodec crate hasn't been updated with it yet.
                // TODO: Replace with ssi_multicodec::ED448_PRIV when ssi-multicodec is updated.
                0x1311
            }
            KeyType::P256 => ssi_multicodec::P256_PRIV,
            KeyType::P384 => ssi_multicodec::P384_PRIV,
            KeyType::P521 => ssi_multicodec::P521_PRIV,
            KeyType::RSA => ssi_multicodec::RSA_PRIV,
            KeyType::Secp256k1 => ssi_multicodec::SECP256K1_PRIV,
            KeyType::Sr25519 => ssi_multicodec::SR25519_PRIV,
            KeyType::X25519 => ssi_multicodec::X25519_PRIV,
        }
    }
    /// Get the multicodec public key codec value for this key type.
    #[cfg(feature = "ssi-multicodec")]
    pub fn as_pub_key_codec(self) -> u64 {
        match self {
            KeyType::Ed25519 => ssi_multicodec::ED25519_PUB,
            KeyType::Ed448 => ssi_multicodec::ED448_PUB,
            KeyType::P256 => ssi_multicodec::P256_PUB,
            KeyType::P384 => ssi_multicodec::P384_PUB,
            KeyType::P521 => ssi_multicodec::P521_PUB,
            KeyType::RSA => ssi_multicodec::RSA_PUB,
            KeyType::Secp256k1 => ssi_multicodec::SECP256K1_PUB,
            KeyType::Sr25519 => ssi_multicodec::SR25519_PUB,
            KeyType::X25519 => ssi_multicodec::X25519_PUB,
        }
    }
    /// Try to convert a multicodec private key codec value to KeyType.
    #[cfg(feature = "ssi-multicodec")]
    pub fn try_from_priv_key_codec(codec: u64) -> Result<Self> {
        match codec {
            ssi_multicodec::ED25519_PRIV => Ok(KeyType::Ed25519),
            // Note that this codec was merged into multicodec in https://github.com/multiformats/multicodec/pull/390,
            // but ssi-multicodec crate hasn't been updated with it yet.
            // TODO: Replace with ssi_multicodec::ED448_PRIV when ssi-multicodec is updated.
            0x1311 => Ok(KeyType::Ed448),
            ssi_multicodec::P256_PRIV => Ok(KeyType::P256),
            ssi_multicodec::P384_PRIV => Ok(KeyType::P384),
            ssi_multicodec::P521_PRIV => Ok(KeyType::P521),
            ssi_multicodec::RSA_PRIV => Ok(KeyType::RSA),
            ssi_multicodec::SECP256K1_PRIV => Ok(KeyType::Secp256k1),
            ssi_multicodec::SR25519_PRIV => Ok(KeyType::Sr25519),
            ssi_multicodec::X25519_PRIV => Ok(KeyType::X25519),
            _ => {
                // #[cfg(feature = "codec-str")]
                // bail!(
                //     "Unknown/unsupported private key type codec: {} (0x{:02x})",
                //     crate::codec_str(codec).unwrap_or(""),
                //     codec
                // );
                // #[cfg(not(feature = "codec-str"))]
                bail!(
                    "Unknown/unsupported private key type codec: 0x{:02x}",
                    codec
                );
            }
        }
    }
    /// Try to convert a multicodec public key codec value to KeyType.
    #[cfg(feature = "ssi-multicodec")]
    pub fn try_from_pub_key_codec(codec: u64) -> Result<Self> {
        match codec {
            ssi_multicodec::ED25519_PUB => Ok(KeyType::Ed25519),
            ssi_multicodec::ED448_PUB => Ok(KeyType::Ed448),
            ssi_multicodec::P256_PUB => Ok(KeyType::P256),
            ssi_multicodec::P384_PUB => Ok(KeyType::P384),
            ssi_multicodec::P521_PUB => Ok(KeyType::P521),
            ssi_multicodec::RSA_PUB => Ok(KeyType::RSA),
            ssi_multicodec::SECP256K1_PUB => Ok(KeyType::Secp256k1),
            ssi_multicodec::SR25519_PUB => Ok(KeyType::Sr25519),
            ssi_multicodec::X25519_PUB => Ok(KeyType::X25519),
            _ => {
                // #[cfg(feature = "codec-str")]
                // bail!(
                //     "Unknown/unsupported public key type codec: {} (0x{:02x})",
                //     crate::codec_str(codec).unwrap_or(""),
                //     codec
                // );
                // #[cfg(not(feature = "codec-str"))]
                bail!("Unknown/unsupported public key type codec: 0x{:02x}", codec);
            }
        }
    }
    /// Try to convert a multicodec codec value to KeyType, which can be either a private or
    /// public key codec.
    #[cfg(feature = "ssi-multicodec")]
    pub fn try_from_codec(codec: u64) -> Result<Self> {
        match codec {
            ssi_multicodec::ED25519_PRIV | ssi_multicodec::ED25519_PUB => Ok(KeyType::Ed25519),
            // Note that this codec was merged into multicodec in https://github.com/multiformats/multicodec/pull/390,
            // but ssi-multicodec crate hasn't been updated with it yet.
            // TODO: Replace with ssi_multicodec::ED448_PRIV when ssi-multicodec is updated.
            0x1311 => Ok(KeyType::Ed448),
            ssi_multicodec::ED448_PUB => Ok(KeyType::Ed448),
            ssi_multicodec::P256_PRIV | ssi_multicodec::P256_PUB => Ok(KeyType::P256),
            ssi_multicodec::P384_PRIV | ssi_multicodec::P384_PUB => Ok(KeyType::P384),
            ssi_multicodec::P521_PRIV | ssi_multicodec::P521_PUB => Ok(KeyType::P521),
            ssi_multicodec::RSA_PRIV | ssi_multicodec::RSA_PUB => Ok(KeyType::RSA),
            ssi_multicodec::SECP256K1_PRIV | ssi_multicodec::SECP256K1_PUB => {
                Ok(KeyType::Secp256k1)
            }
            ssi_multicodec::SR25519_PRIV | ssi_multicodec::SR25519_PUB => Ok(KeyType::Sr25519),
            ssi_multicodec::X25519_PRIV | ssi_multicodec::X25519_PUB => Ok(KeyType::X25519),
            _ => {
                // #[cfg(feature = "codec-str")]
                // bail!(
                //     "Unknown/unsupported private/public key type codec: {} (0x{:02x})",
                //     crate::codec_str(codec).unwrap_or(""),
                //     codec
                // );
                // #[cfg(not(feature = "codec-str"))]
                bail!(
                    "Unknown/unsupported private/public key type codec: 0x{:02x}",
                    codec
                );
            }
        }
    }
    /// Generate a random private key for this key type.  Note that each KeyType variant requires
    /// enabling the feature for the corresponding crate.
    #[cfg(feature = "random")]
    pub fn generate_random_private_key(self) -> Box<dyn crate::ExtractableSignerT + Send + Sync> {
        use crate::GenerateRandom;
        match self {
            KeyType::Ed25519 => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    Box::new(ed25519_dalek::SigningKey::generate_random())
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    panic!("ed25519-dalek feature not enabled");
                }
            }
            KeyType::Ed448 => {
                #[cfg(feature = "ed448-goldilocks")]
                {
                    Box::new(ed448_goldilocks::SigningKey::generate_random())
                }
                #[cfg(not(feature = "ed448-goldilocks"))]
                {
                    panic!("ed448-goldilocks feature not enabled");
                }
            }
            KeyType::P256 => {
                #[cfg(feature = "p256")]
                {
                    Box::new(p256::ecdsa::SigningKey::generate_random())
                }
                #[cfg(not(feature = "p256"))]
                {
                    panic!("p256 feature not enabled");
                }
            }
            KeyType::P384 => {
                #[cfg(feature = "p384")]
                {
                    Box::new(p384::ecdsa::SigningKey::generate_random())
                }
                #[cfg(not(feature = "p384"))]
                {
                    panic!("p384 feature not enabled");
                }
            }
            KeyType::P521 => {
                #[cfg(feature = "p521")]
                {
                    Box::new(p521::ecdsa::SigningKey::generate_random())
                }
                #[cfg(not(feature = "p521"))]
                {
                    panic!("p521 feature not enabled");
                }
            }
            KeyType::Secp256k1 => {
                #[cfg(feature = "k256")]
                {
                    Box::new(k256::ecdsa::SigningKey::generate_random())
                }
                #[cfg(not(feature = "k256"))]
                {
                    panic!("k256 feature not enabled");
                }
            }
            _ => {
                panic!(
                    "KeyType::generate_random_private_key: unsupported key type: {:?}",
                    self
                )
            }
        }
    }
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for KeyType {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for KeyType {
    type Error = Error;
    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        for &key_type in KEY_TYPE_V {
            if s.eq_ignore_ascii_case(key_type.as_str()) {
                return Ok(key_type);
            }
        }
        bail!("Unknown/unsupported key type: {:?}", s);
    }
}
