use std::borrow::Cow;

use crate::{
    ED448_JOSE_ALGORITHM, ED25519_JOSE_ALGORITHM, P256_JOSE_ALGORITHM, P384_JOSE_ALGORITHM,
    P521_JOSE_ALGORITHM, Result, SECP256K1_JOSE_ALGORITHM, SignatureT, bail,
};

// TODO: impl Zeroize
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct SignatureBytes<'a> {
    pub(crate) jose_algorithm: &'static str,
    pub(crate) byte_v: Cow<'a, [u8]>,
}

impl<'a> SignatureBytes<'a> {
    pub fn new(jose_algorithm: &str, byte_v: Cow<'a, [u8]>) -> Result<Self> {
        let jose_algorithm = match jose_algorithm {
            ED25519_JOSE_ALGORITHM => {
                // TODO: Validation -- in this case, just check that byte_v.len() == 32
                ED25519_JOSE_ALGORITHM
            }
            ED448_JOSE_ALGORITHM => {
                // TODO: Validation -- in this case, just check that byte_v.len() == 57
                ED448_JOSE_ALGORITHM
            }
            P256_JOSE_ALGORITHM => {
                // TODO: Validation
                P256_JOSE_ALGORITHM
            }
            P384_JOSE_ALGORITHM => {
                // TODO: Validation
                P384_JOSE_ALGORITHM
            }
            P521_JOSE_ALGORITHM => {
                // TODO: Validation
                P521_JOSE_ALGORITHM
            }
            SECP256K1_JOSE_ALGORITHM => {
                // TODO: Validation
                SECP256K1_JOSE_ALGORITHM
            }
            _ => bail!("Unsupported signature algorithm: {}", jose_algorithm),
        };
        Ok(Self {
            jose_algorithm,
            byte_v,
        })
    }
    pub fn jose_algorithm(&self) -> &'static str {
        self.jose_algorithm
    }
    pub fn bytes(&self) -> &[u8] {
        self.byte_v.as_ref()
    }
    pub fn into_owned<'b>(self) -> SignatureBytes<'b> {
        SignatureBytes {
            jose_algorithm: self.jose_algorithm,
            byte_v: Cow::Owned(self.byte_v.into_owned()),
        }
    }
    pub fn to_owned<'b>(&self) -> SignatureBytes<'b> {
        SignatureBytes {
            jose_algorithm: self.jose_algorithm,
            byte_v: Cow::Owned(self.byte_v.to_vec()),
        }
    }
}

impl<'a> SignatureT for SignatureBytes<'a> {
    fn jose_algorithm(&self) -> &'static str {
        self.jose_algorithm
    }
    fn get_raw_bytes<'b, 's: 'b>(&'s self) -> Cow<'b, [u8]> {
        self.byte_v.clone()
    }
    fn to_signature_bytes<'b, 's: 'b>(&'s self) -> SignatureBytes<'b> {
        self.clone()
    }
}
