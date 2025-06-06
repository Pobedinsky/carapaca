// Elliptic Curve Cryptography and ElGamal Encryption Implementation
// This file provides ECC key generation, hybrid encryption/decryption operations
// It implements a modified ElGamal scheme with AES-GCM and HMAC authentication
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
use base64::{engine::general_purpose, Engine as _}; // For Base64 encoding
use std::fs::File;
use std::io::Write;
use k256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use std::path::Path;
use k256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use std::fs;


type HmacSha256 = Hmac<Sha256>;

// Generate a new ECC key pair (private and public key)
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random(&mut OsRng);
    let pk = sk.public_key();
    (sk, pk)
}

/// Store ECC private and public keys in `.pem` files
/// Arguments:
/// * `sk` - The private key to save
/// * `pk` - The public key to save
/// * `priv_path` - Path to save the private key
/// * `pub_path` - Path to save the public key
pub fn save_keypair_to_pem(sk: &SecretKey, pk: &PublicKey, priv_path: &str, pub_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Encode private key in PKCS#8 PEM format
    let private_pem = sk.to_pkcs8_pem(Default::default())?;
    let mut priv_file = File::create(priv_path)?;
    priv_file.write_all(private_pem.as_bytes())?;

    // Encode public key in PEM (SEC1) format
    let public_pem = pk.to_public_key_pem(Default::default())?;
    let mut pub_file = File::create(pub_path)?;
    pub_file.write_all(public_pem.as_bytes())?;
    Ok(())
}

/// Read an ECC private key from a PEM file
/// Arguments:
/// * `path` - Path to the private key PEM file
/// Returns: Result<SecretKey, Box<dyn std::error::Error>> - The loaded private key or an error
pub fn load_private_key_from_pem<P: AsRef<Path>>(path: P) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let pem = fs::read_to_string(path)?;
    let sk = SecretKey::from_pkcs8_pem(&pem)?;
    Ok(sk)
}

/// Read an ECC public key from a PEM file
/// Arguments:
/// * `path` - Path to the public key PEM file
/// Returns: Result<PublicKey, Box<dyn std::error::Error>> - The loaded public key or an error
pub fn load_public_key_from_pem<P: AsRef<Path>>(path: P) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let pem = fs::read_to_string(path)?;
    let pk = PublicKey::from_public_key_pem(&pem)?;
    Ok(pk)
}

// Encrypt a message using the recipient's public key with hybrid encryption
// Uses ECC for key agreement, AES-GCM for symmetric encryption, and HMAC for authentication
pub fn encrypt(pk: &PublicKey, message: &[u8]) -> String {
    // Generate a random ephemeral key for this encryption session
    let d_b = SecretKey::random(&mut OsRng);
    let y = PublicKey::from_secret_scalar(&d_b.to_nonzero_scalar());
    let x_point = ProjectivePoint::from(*pk.as_affine());
    let k_point = x_point * *d_b.to_nonzero_scalar();
    let k_bytes = k_point.to_affine().x().to_vec();

    // Derive encryption and authentication keys using HKDF
    let hk = Hkdf::<Sha256>::new(None, &k_bytes);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    hk.expand(b"enc", &mut k1).unwrap();
    hk.expand(b"mac", &mut k2).unwrap();

    // Encrypt the message with AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&k1).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);
    let ciphertext = cipher.encrypt(nonce, message).unwrap();

    // Create HMAC authentication tag
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&k2).unwrap();
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes().to_vec();

    // Encode each component in Base64
    let y_base64 = general_purpose::STANDARD.encode(y.to_encoded_point(false).as_bytes());
    let ciphertext_base64 = general_purpose::STANDARD.encode(&ciphertext);
    let tag_base64 = general_purpose::STANDARD.encode(&tag);

    // Combine into a single string with ":" delimiter
    format!("{}:{}:{}", y_base64, ciphertext_base64, tag_base64)
}

// Decrypt a message using the recipient's private key
// Arguments:
// * `sk` - The private key to decrypt with
// * `base64_input` - The Base64 encoded encrypted message
// Returns: Result<Vec<u8>, &'static str> - The decrypted message or an error
pub fn decrypt(sk: &SecretKey, base64_input: &str) -> Result<Vec<u8>, &'static str> {
    // Split the Base64 string into components
    let parts: Vec<&str> = base64_input.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid Base64 input format");
    }

    // Decode each component
    let y_bytes = general_purpose::STANDARD
        .decode(parts[0])
        .map_err(|_| "Failed to decode y_point")?;
    let ciphertext = general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|_| "Failed to decode ciphertext")?;
    let tag = general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|_| "Failed to decode tag")?;

    // Convert y_bytes to EncodedPoint
    let y_point = EncodedPoint::from_bytes(&y_bytes).map_err(|_| "Invalid y_point format")?;

    let y_pub = PublicKey::from_sec1_bytes(y_point.as_bytes()).map_err(|_| "Invalid public key")?;
    let y_proj = ProjectivePoint::from(*y_pub.as_affine());

    // Perform key agreement to derive the shared secret
    let k_point = y_proj * *sk.to_nonzero_scalar();
    let k_bytes = k_point.to_affine().x().to_vec();

    // Derive the same encryption and authentication keys
    let hk = Hkdf::<Sha256>::new(None, &k_bytes);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    hk.expand(b"enc", &mut k1).unwrap();
    hk.expand(b"mac", &mut k2).unwrap();

    // Verify the HMAC tag
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&k2).unwrap();
    mac.update(&ciphertext);
    mac.verify_slice(&tag).map_err(|_| "MAC verification failed")?;

    // Decrypt the message with AES-GCM
    let cipher = Aes256Gcm::new_from_slice(&k1).unwrap();
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher
        .decrypt(nonce, &ciphertext[..])
        .map_err(|_| "Decryption error")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (sk, pk) = generate_keypair();
        let message = b"Ultra important secret message";

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
}
