/// Trait for types that can be generated via a cryptographically random process.
pub trait GenerateRandom {
    /// Return a new, cryptographically random instance of this SignerT.
    fn generate_random() -> Self;
}
