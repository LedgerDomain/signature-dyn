#[cfg(feature = "signature")]
fn test_sign_verify_commutative_diagram_case<Signature, Signer, Verifier>(
    signer: Signer,
    verifier: Verifier,
) where
    Signature: signature_dyn::SignatureDynT,
    Signer: signature::Signer<Signature> + signature_dyn::SignerDynT,
    Verifier: signature::Verifier<Signature> + signature_dyn::VerifierDynT,
{
    use signature_dyn::{SignerDynT, VerifierDynT};

    let message = b"HIPPO";

    let verifier_dyn_b = signer.verifier_dyn().expect("pass");
    let signature: Signature = signer.sign(message);
    verifier.verify(message, &signature).expect("pass");
    let expected_signature_bytes = signature.to_signature_bytes();

    let signer_bytes = signer.to_signer_bytes();
    let verifier_bytes = verifier.to_verifier_bytes();
    let signature_b = signer_bytes.sign_message(message);
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
    assert_eq!(
        verifier_dyn_b.to_verifier_bytes(),
        verifier.to_verifier_bytes()
    );
    assert_eq!(verifier_dyn_b.to_verifier_bytes(), verifier_bytes);
}

fn test_sign_verify_commutative_diagram_case_signature_3<Signature, Signer, Verifier>(
    signer: Signer,
    verifier: Verifier,
) where
    Signature: signature_dyn::SignatureDynT,
    Signer: signature_3::Signer<Signature> + signature_dyn::SignerDynT,
    Verifier: signature_3::Verifier<Signature> + signature_dyn::VerifierDynT,
{
    use signature_dyn::{SignerDynT, VerifierDynT};

    let message = b"HIPPO";

    let signature: Signature = signer.try_sign(message).expect("pass");
    verifier.verify(message, &signature).expect("pass");
    let expected_signature_bytes = signature.to_signature_bytes();

    let signer_bytes = signer.to_signer_bytes();
    let verifier_bytes = verifier.to_verifier_bytes();
    let signature_b = signer_bytes.sign_message(message);
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
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
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
    let signing_key = ed448_goldilocks::SigningKey::generate(&mut rand_0_9::rand_core::UnwrapMut(
        &mut rand_0_9::rngs::OsRng,
    ));
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case_signature_3(signing_key, verifying_key);
}

#[cfg(all(feature = "ed448-goldilocks", feature = "random"))]
#[test]
fn test_ed448_goldilocks_generate_random() {
    use signature_dyn::GenerateRandom;
    let signing_key = ed448_goldilocks::SigningKey::generate_random();
    let verifying_key = signing_key.verifying_key();
    test_sign_verify_commutative_diagram_case_signature_3(signing_key, verifying_key);
}

#[cfg(feature = "k256")]
#[test]
fn test_k256() {
    let signing_key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
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
    let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
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
    let signing_key = p384::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
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
    let signing_key = p521::ecdsa::SigningKey::random(&mut rand_0_9::rand_core::UnwrapMut(
        &mut rand_0_9::rngs::OsRng,
    ));
    let verifying_key = signing_key.verifying_key().clone();
    test_sign_verify_commutative_diagram_case_signature_3::<p521::ecdsa::Signature, _, _>(
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
    test_sign_verify_commutative_diagram_case_signature_3::<p521::ecdsa::Signature, _, _>(
        signing_key,
        verifying_key,
    );
}

#[cfg(feature = "random")]
fn test_generate_random_impl(key_type: signature_dyn::KeyType) {
    let message = b"HIPPO";
    let signer_b = key_type.generate_random_private_key();
    let signature_b = signer_b.sign_message(message);
    let verifier_b = signer_b.verifier_dyn().expect("pass");
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
    PrivKey: signature_dyn::PKCS8Write + signature_dyn::PKCS8Read + signature_dyn::SignerDynT,
>(
    key_type: signature_dyn::KeyType,
    priv_key: &PrivKey,
) {
    let path = std::path::PathBuf::from(format!("test.{:?}.pem", key_type));
    // use signature_dyn::PKCS8Write;
    priv_key.write_to_pkcs8_pem_file(&path).expect("pass");
    // use signature_dyn::PKCS8Read;
    let priv_key_from_disk = PrivKey::read_from_pkcs8_pem_file(&path).expect("pass");
    assert_eq!(
        priv_key_from_disk.to_signer_bytes(),
        priv_key.to_signer_bytes()
    );
}

#[cfg(all(feature = "pkcs8", feature = "random"))]
#[test]
fn test_pkcs8() {
    use signature_dyn::{GenerateRandom, SignerDynT};

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
