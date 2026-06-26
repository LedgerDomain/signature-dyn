fn test_sign_verify_commutative_diagram_case<Signature, Signer, Verifier>(
    signer: Signer,
    verifier: Verifier,
) where
    Signature: signature_dyn::SignatureT,
    Signer:
        signature::Signer<Signature> + signature_dyn::ExtractableSignerT + signature_dyn::SignerT,
    Verifier: signature::Verifier<Signature> + signature_dyn::VerifierT,
{
    use signature_dyn::{SignerT, VerifierT};

    let message = b"HIPPO";

    let signature: Signature = signer.try_sign(message).expect("pass");
    verifier.verify(message, &signature).expect("pass");
    let expected_signature_bytes = signature.to_signature_bytes();

    let signer_bytes = signer.extract_signer_bytes().expect("pass");
    let verifier_bytes = verifier.to_verifier_bytes();
    let signature_b = signer_bytes.try_sign_message(message).expect("pass");
    verifier_bytes
        .verify_message(message, signature_b.as_ref())
        .expect("pass");
    let signature_bytes = signature_b.to_signature_bytes();

    println!(
        "-- signature algorithm: {:?} -----------------------------",
        signature_bytes.jose_algorithm()
    );
    println!("signature_bytes: {:?}", signature_bytes);
    println!("expected_signature_bytes: {:?}", expected_signature_bytes);
    assert_eq!(signature_bytes, expected_signature_bytes);
}

#[cfg(feature = "async")]
#[cfg(feature = "signature")]
async fn test_sign_verify_commutative_diagram_case_async<Signature, Signer, Verifier>(
    signer: Signer,
    verifier: Verifier,
) where
    Signature: signature_dyn::SignatureT,
    Signer: signature::Signer<Signature>
        + signature_dyn::AsyncExtractableSignerT
        + signature_dyn::AsyncSignerT
        + Send
        + Sync,
    Verifier: signature::Verifier<Signature> + signature_dyn::VerifierT,
{
    use signature_dyn::{SignerT, VerifierT};

    let message = b"HIPPO";

    let signature: Signature = signer.try_sign(message).expect("pass");
    verifier.verify(message, &signature).expect("pass");
    let expected_signature_bytes = signature.to_signature_bytes();

    let signer_bytes = signer.async_extract_signer_bytes().await.expect("pass");
    let verifier_bytes = verifier.to_verifier_bytes();
    let signature_b = signer_bytes.try_sign_message(message).expect("pass");
    verifier_bytes
        .verify_message(message, signature_b.as_ref())
        .expect("pass");
    let signature_bytes = signature_b.to_signature_bytes();

    println!(
        "-- signature algorithm: {:?} -----------------------------",
        signature_bytes.jose_algorithm()
    );
    println!("signature_bytes: {:?}", signature_bytes);
    println!("expected_signature_bytes: {:?}", expected_signature_bytes);
    assert_eq!(signature_bytes, expected_signature_bytes);
}

#[cfg(feature = "ed25519-dalek")]
#[test]
fn test_ed25519_dalek() {
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case(signing_key, verifying_key);
}

#[cfg(all(feature = "ed25519-dalek", feature = "random"))]
#[test]
fn test_ed25519_dalek_generate_random() {
    use signature_dyn::GenerateRandom;
    let signing_key = ed25519_dalek::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case(signing_key, verifying_key);
}

#[cfg(feature = "ed448-goldilocks")]
#[test]
fn test_ed448_goldilocks() {
    use ed448_goldilocks::elliptic_curve::Generate;
    let signing_key = ed448_goldilocks::SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case(signing_key, verifying_key);
}

#[cfg(all(feature = "ed448-goldilocks", feature = "random"))]
#[test]
fn test_ed448_goldilocks_generate_random() {
    use signature_dyn::GenerateRandom;
    let signing_key = ed448_goldilocks::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case(signing_key, verifying_key);
}

#[cfg(feature = "k256")]
#[test]
fn test_k256() {
    use k256::elliptic_curve::Generate;
    let signing_key = k256::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<k256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(all(feature = "k256", feature = "random"))]
#[test]
fn test_k256_generate_random() {
    use signature_dyn::GenerateRandom;
    let signing_key = k256::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<k256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(feature = "p256")]
#[test]
fn test_p256() {
    use p256::elliptic_curve::Generate;
    let signing_key = p256::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<p256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(all(feature = "p256", feature = "random"))]
#[test]
fn test_p256_generate_random() {
    use signature_dyn::GenerateRandom;
    let signing_key = p256::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<p256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(feature = "p384")]
#[test]
fn test_p384() {
    use p384::elliptic_curve::Generate;
    let signing_key = p384::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<p384::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(all(feature = "p384", feature = "random"))]
#[test]
fn test_p384_generate_random() {
    use signature_dyn::GenerateRandom;
    let signing_key = p384::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<p384::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(feature = "p521")]
#[test]
fn test_p521() {
    use p521::elliptic_curve::Generate;
    let signing_key = p521::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<p521::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(all(feature = "p521", feature = "random"))]
#[test]
fn test_p521_generate_random() {
    use signature_dyn::GenerateRandom;
    let signing_key = p521::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case::<p521::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(all(feature = "async", feature = "ed25519-dalek"))]
#[tokio::test]
async fn test_ed25519_dalek_async() {
    let mut rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case_async(signing_key, verifying_key).await;
}

#[cfg(all(feature = "async", feature = "ed25519-dalek", feature = "random"))]
#[tokio::test]
async fn test_ed25519_dalek_generate_random_async() {
    use signature_dyn::GenerateRandom;
    let signing_key = ed25519_dalek::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case_async(signing_key, verifying_key).await;
}

#[cfg(all(feature = "async", feature = "ed448-goldilocks"))]
#[tokio::test]
async fn test_ed448_goldilocks_async() {
    use ed448_goldilocks::elliptic_curve::Generate;
    let signing_key = ed448_goldilocks::SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case_async(signing_key, verifying_key).await;
}

#[cfg(all(feature = "async", feature = "ed448-goldilocks", feature = "random"))]
#[tokio::test]
async fn test_ed448_goldilocks_generate_random_async() {
    use signature_dyn::GenerateRandom;
    let signing_key = ed448_goldilocks::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case_async(signing_key, verifying_key).await;
}

#[cfg(all(feature = "async", feature = "k256"))]
#[tokio::test]
async fn test_k256_async() {
    use k256::elliptic_curve::Generate;
    let signing_key = k256::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<k256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(all(feature = "async", feature = "k256", feature = "random"))]
#[tokio::test]
async fn test_k256_generate_random_async() {
    use signature_dyn::GenerateRandom;
    let signing_key = k256::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<k256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(all(feature = "async", feature = "p256"))]
#[tokio::test]
async fn test_p256_async() {
    use p256::elliptic_curve::Generate;
    let signing_key = p256::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<p256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(all(feature = "async", feature = "p256", feature = "random"))]
#[tokio::test]
async fn test_p256_generate_random_async() {
    use signature_dyn::GenerateRandom;
    let signing_key = p256::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<p256::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(all(feature = "async", feature = "p384"))]
#[tokio::test]
async fn test_p384_async() {
    use p384::elliptic_curve::Generate;
    let signing_key = p384::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<p384::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(all(feature = "async", feature = "p384", feature = "random"))]
#[tokio::test]
async fn test_p384_generate_random_async() {
    use signature_dyn::GenerateRandom;
    let signing_key = p384::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<p384::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(all(feature = "async", feature = "p521"))]
#[tokio::test]
async fn test_p521_async() {
    use p521::elliptic_curve::Generate;
    let signing_key = p521::ecdsa::SigningKey::generate();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<p521::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(all(feature = "async", feature = "p521", feature = "random"))]
#[tokio::test]
async fn test_p521_generate_random_async() {
    use signature_dyn::GenerateRandom;
    let signing_key = p521::ecdsa::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_async::<p521::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    )
    .await;
}

#[cfg(feature = "random")]
fn test_generate_random_impl(key_type: signature_dyn::KeyType) {
    let message = b"HIPPO";
    let signer_b = key_type.generate_random_private_key();
    let signature_b = signer_b.try_sign_message(message).expect("pass");
    let verifier_b = signer_b.get_verifier().expect("pass");
    verifier_b
        .verify_message(message, signature_b.as_ref())
        .expect("pass");
}

#[cfg(feature = "random")]
#[test]
fn test_generate_random() {
    use signature_dyn::KeyType;

    #[cfg(feature = "ed25519-dalek")]
    test_generate_random_impl(KeyType::Ed25519);

    #[cfg(feature = "ed448-goldilocks")]
    test_generate_random_impl(KeyType::Ed448);

    #[cfg(feature = "k256")]
    test_generate_random_impl(KeyType::Secp256k1);

    #[cfg(feature = "p256")]
    test_generate_random_impl(KeyType::P256);

    #[cfg(feature = "p384")]
    test_generate_random_impl(KeyType::P384);

    #[cfg(feature = "p521")]
    test_generate_random_impl(KeyType::P521);
}

#[cfg(feature = "pkcs8")]
fn test_pkcs8_impl<
    PrivKey: signature_dyn::ExtractableSignerT
        + signature_dyn::PKCS8Write
        + signature_dyn::PKCS8Read
        + signature_dyn::SignerT,
>(
    key_type: signature_dyn::KeyType,
    priv_key: &PrivKey,
) {
    let path = std::path::PathBuf::from(format!("test.{:?}.pem", key_type));
    priv_key.write_to_pkcs8_pem_file(&path).expect("pass");
    let priv_key_from_disk = PrivKey::read_from_pkcs8_pem_file(&path).expect("pass");
    assert_eq!(
        priv_key_from_disk.extract_signer_bytes().expect("pass"),
        priv_key.extract_signer_bytes().expect("pass")
    );
}

#[cfg(all(feature = "pkcs8", feature = "random"))]
#[test]
fn test_pkcs8() {
    use signature_dyn::{GenerateRandom, SignerT};

    #[cfg(feature = "ed25519-dalek")]
    {
        let signing_key = ed25519_dalek::SigningKey::generate_random();
        test_pkcs8_impl(signing_key.key_type(), &signing_key);
    }

    #[cfg(feature = "ed448-goldilocks")]
    {
        let signing_key = ed448_goldilocks::SigningKey::generate_random();
        test_pkcs8_impl(signing_key.key_type(), &signing_key);
    }

    #[cfg(feature = "p256")]
    {
        let signing_key = p256::ecdsa::SigningKey::generate_random();
        test_pkcs8_impl(signing_key.key_type(), &signing_key);
    }

    #[cfg(feature = "p384")]
    {
        let signing_key = p384::ecdsa::SigningKey::generate_random();
        test_pkcs8_impl(signing_key.key_type(), &signing_key);
    }

    #[cfg(feature = "p521")]
    {
        let signing_key = p521::ecdsa::SigningKey::generate_random();
        test_pkcs8_impl(signing_key.key_type(), &signing_key);
    }

    #[cfg(feature = "k256")]
    {
        let signing_key = k256::ecdsa::SigningKey::generate_random();
        test_pkcs8_impl(signing_key.key_type(), &signing_key);
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_as_async_signer() {
    async fn feed_me_an_async_signer(
        async_signer: &(dyn signature_dyn::AsyncSignerT + Send + Sync),
    ) {
        let signature_b = async_signer
            .async_try_sign_message(b"HIPPO")
            .await
            .expect("pass");
        let verifier_b = async_signer.async_get_verifier().await.expect("pass");
        verifier_b
            .verify_message(b"HIPPO", signature_b.as_ref())
            .expect("pass");
    }

    use signature_dyn::GenerateRandom;
    let signing_key = ed25519_dalek::SigningKey::generate_random();

    feed_me_an_async_signer(&signature_dyn::AsAsyncSigner::new(&signing_key)).await;

    {
        // Type erasure so that we test the cast from SignerT to AsyncSignerT.
        let signer_b: Box<dyn signature_dyn::SignerT + Send + Sync> = Box::new(signing_key);
        feed_me_an_async_signer(&signature_dyn::AsAsyncSigner::new(signer_b.as_ref())).await;
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn test_as_async_extractable_signer() {
    async fn feed_me_an_async_extractable_signer(
        async_extractable_signer: &(dyn signature_dyn::AsyncExtractableSignerT + Send + Sync),
    ) {
        let signer_bytes = async_extractable_signer
            .async_extract_signer_bytes()
            .await
            .expect("pass");
        use signature_dyn::SignerT;
        let signature_b = signer_bytes.try_sign_message(b"HIPPO").expect("pass");
        let verifier_b = signer_bytes.get_verifier().expect("pass");
        verifier_b
            .verify_message(b"HIPPO", signature_b.as_ref())
            .expect("pass");
    }

    use signature_dyn::GenerateRandom;
    let signing_key = ed25519_dalek::SigningKey::generate_random();

    feed_me_an_async_extractable_signer(&signature_dyn::AsAsyncExtractableSigner::new(
        &signing_key,
    ))
    .await;

    {
        // Type erasure so that we test the cast from SignerT to AsyncSignerT.
        let signer_b: Box<dyn signature_dyn::ExtractableSignerT + Send + Sync> =
            Box::new(signing_key);
        feed_me_an_async_extractable_signer(&signature_dyn::AsAsyncExtractableSigner::new(
            signer_b.as_ref(),
        ))
        .await;
    }
}

#[test]
fn test_priv_key_byte_lengths() {
    #[cfg(feature = "ed25519-dalek")]
    {
        use signature_dyn::{ExtractableSignerT, GenerateRandom};
        let signing_key = ed25519_dalek::SigningKey::generate_random();
        let signer_bytes = signing_key.extract_signer_bytes().expect("pass");
        assert_eq!(signer_bytes.bytes().len(), 32);
    }
    #[cfg(feature = "ed448-goldilocks")]
    {
        use signature_dyn::{ExtractableSignerT, GenerateRandom};
        let signing_key = ed448_goldilocks::SigningKey::generate_random();
        let signer_bytes = signing_key.extract_signer_bytes().expect("pass");
        assert_eq!(signer_bytes.bytes().len(), 57);
    }
    #[cfg(feature = "k256")]
    {
        use signature_dyn::{ExtractableSignerT, GenerateRandom};
        let signing_key = k256::ecdsa::SigningKey::generate_random();
        let signer_bytes = signing_key.extract_signer_bytes().expect("pass");
        assert_eq!(signer_bytes.bytes().len(), 32);
    }
    #[cfg(feature = "p256")]
    {
        use signature_dyn::{ExtractableSignerT, GenerateRandom};
        let signing_key = p256::ecdsa::SigningKey::generate_random();
        let signer_bytes = signing_key.extract_signer_bytes().expect("pass");
        assert_eq!(signer_bytes.bytes().len(), 32);
    }
    #[cfg(feature = "p384")]
    {
        use signature_dyn::{ExtractableSignerT, GenerateRandom};
        let signing_key = p384::ecdsa::SigningKey::generate_random();
        let signer_bytes = signing_key.extract_signer_bytes().expect("pass");
        assert_eq!(signer_bytes.bytes().len(), 48);
    }
    #[cfg(feature = "p521")]
    {
        use signature_dyn::{ExtractableSignerT, GenerateRandom};
        let signing_key = p521::ecdsa::SigningKey::generate_random();
        let signer_bytes = signing_key.extract_signer_bytes().expect("pass");
        assert_eq!(signer_bytes.bytes().len(), 66);
    }
}
