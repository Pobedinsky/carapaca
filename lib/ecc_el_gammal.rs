use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand_core::OsRng;
use k256::{
    EncodedPoint, ProjectivePoint, PublicKey, SecretKey,
    elliptic_curve::sec1::ToEncodedPoint,
    elliptic_curve::point::AffineCoordinates,
};
use hmac::digest::KeyInit as HmacKeyInit;
use base64::{engine::general_purpose, Engine as _};
use std::fs::File;
use std::io::Write;
use k256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use std::path::Path;
use k256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use std::fs;
use k256::ecdsa::{
    signature::{Signer, Verifier}, SigningKey, VerifyingKey, Signature,
};

type HmacSha256 = Hmac<Sha256>;

pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = sk.public_key();
    (sk, pk)
}


pub fn sign_to_base64(sk: &SecretKey, message: &[u8]) -> String {
    let signing_key = SigningKey::from(sk.clone());
    let signature: Signature = signing_key.sign(message);
    general_purpose::STANDARD.encode(signature.to_der().as_bytes())
}

pub fn verify_signature(pk: &PublicKey, message: &[u8], signature_b64: &str) -> bool {
    let verifying_key = VerifyingKey::from(pk.clone());
    let sig_bytes = general_purpose::STANDARD.decode(signature_b64).unwrap();
    let signature = match Signature::from_der(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    verifying_key.verify(message, &signature).is_ok()
}

/// Guarda a chave privada e pública ECC em ficheiros `.pem`.
pub fn save_keypair_to_pem(sk: &SecretKey, pk: &PublicKey, priv_path: &str, pub_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Codificar chave privada em PKCS#8 PEM
    let private_pem = sk.to_pkcs8_pem(Default::default())?;
    let mut priv_file = File::create(priv_path)?;
    priv_file.write_all(private_pem.as_bytes())?;

    // Codificar chave pública em PEM (SEC1)
    let public_pem = pk.to_public_key_pem(Default::default())?;
    let mut pub_file = File::create(pub_path)?;
    pub_file.write_all(public_pem.as_bytes())?;
    Ok(())
}

pub fn load_private_key_from_pem(path: String) -> SecretKey {
    let pem = fs::read_to_string(Path::new(&path)).unwrap();
    SecretKey::from_pkcs8_pem(&pem).unwrap()
}

pub fn load_public_key_from_pem(path: String) -> PublicKey {
    let pem = fs::read_to_string(Path::new(&path)).unwrap();
    PublicKey::from_public_key_pem(&pem).unwrap()
}

pub fn encrypt(pk: &PublicKey, message: &[u8]) -> String {
    let d_b = SecretKey::random(&mut OsRng);
    let y = PublicKey::from_secret_scalar(&d_b.to_nonzero_scalar());

    let x_point = ProjectivePoint::from(*pk.as_affine());
    let k_point = x_point * *d_b.to_nonzero_scalar();
    let k_bytes = k_point.to_affine().x().to_vec();

    let hk = Hkdf::<Sha256>::new(None, &k_bytes);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    hk.expand(b"enc", &mut k1).unwrap();
    hk.expand(b"mac", &mut k2).unwrap();

    let cipher = Aes256Gcm::new_from_slice(&k1).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let ciphertext = cipher.encrypt(nonce, message).unwrap();

    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&k2).unwrap();
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes().to_vec();

    // Codificar cada componente em Base64
    let y_base64 = general_purpose::STANDARD.encode(y.to_encoded_point(false).as_bytes());
    let ciphertext_base64 = general_purpose::STANDARD.encode(&ciphertext);
    let tag_base64 = general_purpose::STANDARD.encode(&tag);

    // Combinar em uma única string com delimitador ":"
    format!("{}:{}:{}", y_base64, ciphertext_base64, tag_base64)
}

pub fn decrypt(sk: &SecretKey, base64_input: &str) -> Result<Vec<u8>, &'static str> {
    // Separar a string Base64 nos componentes
    let parts: Vec<&str> = base64_input.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid Base64 input format");
    }

    // Decodificar cada componente
    let y_bytes = general_purpose::STANDARD
        .decode(parts[0])
        .map_err(|_| "Failed to decode y_point")?;
    let ciphertext = general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|_| "Failed to decode ciphertext")?;
    let tag = general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|_| "Failed to decode tag")?;

    // Converter y_bytes para EncodedPoint
    let y_point = EncodedPoint::from_bytes(&y_bytes).map_err(|_| "Invalid y_point format")?;

    let y_pub = PublicKey::from_sec1_bytes(y_point.as_bytes()).map_err(|_| "Invalid public key")?;
    let y_proj = ProjectivePoint::from(*y_pub.as_affine());

    let k_point = y_proj * *sk.to_nonzero_scalar();
    let k_bytes = k_point.to_affine().x().to_vec();

    let hk = Hkdf::<Sha256>::new(None, &k_bytes);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    hk.expand(b"enc", &mut k1).unwrap();
    hk.expand(b"mac", &mut k2).unwrap();

    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&k2).unwrap();
    mac.update(&ciphertext);
    mac.verify_slice(&tag).map_err(|_| "Falha no MAC")?;

    let cipher = Aes256Gcm::new_from_slice(&k1).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(nonce, &ciphertext[..])
        .map_err(|_| "Erro de decifração")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (sk, pk) = generate_keypair();
        let message = b"Mensagem secreta ultra importante";

        let encrypted = encrypt(&pk, message);
        let decrypted = decrypt(&sk, &encrypted);

        assert!(decrypted.is_ok(), "Decryption failed"); // Check if decryption was successful
        assert_eq!(decrypted.unwrap(), message); // Ensure the decrypted message matches the original message
    }

    #[test]
    fn test_encrypt_decrypt_empty_message() {
        let (sk, pk) = generate_keypair();
        let message = b"";

        let encrypted = encrypt(&pk, message);
        let decrypted = decrypt(&sk, &encrypted);

        assert!(decrypted.is_ok(), "Decryption failed for empty message");
        assert_eq!(decrypted.unwrap(), message);
    }

    #[test]
    fn test_encrypt_decrypt_special_characters() {
        let (sk, pk) = generate_keypair();
        let message = "💻🔐🚀🔥\n\tSpecial chars and unicode!".as_bytes();

        let encrypted = encrypt(&pk, message);
        let decrypted = decrypt(&sk, &encrypted);

        assert!(decrypted.is_ok(), "Decryption failed for special characters");
        assert_eq!(decrypted.unwrap(), message);
    }

    #[test]
    fn test_encrypt_decrypt_large_message() {
        let (sk, pk) = generate_keypair();
        let message = vec![42u8; 10_000]; // 10 KB message

        let encrypted = encrypt(&pk, &message);
        let decrypted = decrypt(&sk, &encrypted);

        assert!(decrypted.is_ok(), "Decryption failed for large message");
        assert_eq!(decrypted.unwrap(), message);
    }

    #[test]
    fn test_multiple_encryptions_differ() {
        let (_, pk) = generate_keypair();
        let message = b"Same plaintext";

        // Encrypt multiple times
        let encrypted1 = encrypt(&pk, message);
        let encrypted2 = encrypt(&pk, message);

        // They should not be the same due to random ephemeral keys
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_signature_valid() {
        let (sk, pk) = generate_keypair();
        let message = b"Mensagem autentica";

        let signature = sign_to_base64(&sk, message);
        let is_valid = verify_signature(&pk, message, &signature);

        assert!(is_valid, "A assinatura deveria ser válida");
    }

    #[test]
    fn test_signature_invalid_message() {
        let (sk, pk) = generate_keypair();
        let message = b"Mensagem autentica";
        let tampered = b"Mensagem adulterada";

        let signature = sign_to_base64(&sk, message);
        let is_valid = verify_signature(&pk, tampered, &signature);

        assert!(!is_valid, "A assinatura não deveria ser válida com mensagem adulterada");
    }

    #[test]
    fn test_signature_invalid_key() {
        let (sk1, _) = generate_keypair();
        let (_, pk2) = generate_keypair();
        let message = b"Mensagem testada";

        let signature = sign_to_base64(&sk1, message);
        let is_valid = verify_signature(&pk2, message, &signature);

        assert!(!is_valid, "A assinatura não deveria ser válida com chave pública diferente");
    }
}
