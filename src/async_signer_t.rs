use crate::{KeyType, Result, SignatureT, SignerT, VerifierBytes, VerifierT};

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait AsyncSignerT {
    /// Return the key id of this AsyncSignerT -- i.e. the value that should be used in the "kid" field
    /// of a JWS or other signed artifact.  If a key id is unavailable or undefined, return None.
    async fn async_key_id(&self) -> Result<Option<String>>;
    /// Return the key type of this AsyncSignerT.
    async fn async_key_type(&self) -> Result<KeyType>;
    /// Returns the corresponding verifier which can verify signatures that this AsyncSignerT produces.
    async fn async_get_verifier(&self) -> Result<Box<dyn VerifierT>>;
    /// Returns the VerifierBytes representation of `self.verifier_dyn()`, i.e. its pub key.
    /// Default implementation calls `self.verifier_dyn()?.to_verifier_bytes()`.  Can be overridden
    /// to provide a more efficient implementation.
    async fn async_get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self
            .async_get_verifier()
            .await?
            .to_verifier_bytes()
            .into_owned())
    }
    /// Attempt to sign the given message.
    async fn async_try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>>;
}

/// A SignerT has a canonical implementation of AsyncSignerT.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl<S: SignerT + Send + Sync> AsyncSignerT for S {
    async fn async_key_id(&self) -> Result<Option<String>> {
        Ok(self.key_id())
    }
    async fn async_key_type(&self) -> Result<KeyType> {
        Ok(self.key_type())
    }
    async fn async_get_verifier(&self) -> Result<Box<dyn VerifierT>> {
        Ok(self.get_verifier()?)
    }
    async fn async_get_verifier_bytes<'b, 's: 'b>(&'s self) -> Result<VerifierBytes<'b>> {
        Ok(self.get_verifier_bytes()?)
    }
    async fn async_try_sign_message(&self, message_byte_v: &[u8]) -> Result<Box<dyn SignatureT>> {
        Ok(self.try_sign_message(message_byte_v)?)
    }
}
