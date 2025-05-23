/**
 * AES Symmetric Encryption Module
 * 
 * This module provides AES-256-CBC encryption, decryption, and key management
 * functions. It includes utilities for generating random keys, key derivation,
 * and HMAC authentication to ensure data integrity.
 */

use openssl::symm::{encrypt, decrypt, Cipher};    // OpenSSL symmetric encryption
use rand::{RngCore, rngs::OsRng};                // Secure random number generation
use base64::{engine::general_purpose, Engine as _}; // Base64 encoding/decoding
use hmac::{Hmac, Mac};                           // HMAC authentication
use sha2::Sha256;                                // SHA-256 hash function
use hkdf::Hkdf;                                  // HKDF key derivation function

/**
 * Represents an AES-256 key with its initialization vector (IV)
 */
pub struct AES256Key {
    pub key: Vec<u8>, // 32 bytes for AES-256
    pub iv: Vec<u8>,  // 16 bytes initialization vector
}

impl AES256Key {
    /**
     * Generate a cryptographically secure random AES-256 key and IV
     * 
     * @return Self - A new AES256Key instance with random values
     */
    pub fn generate() -> Self {
        // Create buffers for key and IV
        let mut key = vec![0u8; 32];  // AES-256 uses a 32-byte key
        let mut iv = vec![0u8; 16];   // AES uses a 16-byte IV
        
        // Fill with cryptographically secure random bytes
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut iv);
        
        AES256Key { key, iv }
    }

    /**
     * Encode the key and IV as base64 strings
     * 
     * @return (String, String) - Base64-encoded key and IV
     */
    pub fn save_to_base64(&self) -> (String, String) {
        (
            general_purpose::STANDARD.encode(&self.key),
            general_purpose::STANDARD.encode(&self.iv),
        )
    }

    /**
     * Load an AES256Key from base64-encoded key and IV strings
     * 
     * @param key_b64 - Base64-encoded key
     * @param iv_b64 - Base64-encoded IV
     * @return Self - The loaded AES256Key
     */
    pub fn load_from_base64(key_b64: &str, iv_b64: &str) -> Self {
        // Decode base64 strings
        let key = general_purpose::STANDARD.decode(key_b64).expect("Failed to decode key");
        let iv = general_purpose::STANDARD.decode(iv_b64).expect("Failed to decode IV");
        
        // Verify correct lengths
        assert_eq!(key.len(), 32, "AES-256 key must be 32 bytes");
        assert_eq!(iv.len(), 16, "AES IV must be 16 bytes");
        
        AES256Key { key, iv }
    }
}

/**
 * Derive encryption and HMAC keys from a session key and IV
 * 
 * Uses HKDF (HMAC-based Key Derivation Function) to derive two separate
 * cryptographic keys from a single input key: one for AES encryption
 * and another for HMAC authentication.
 *
 * @param k - The session key (32 bytes)
 * @param iv - The initialization vector (16 bytes)
 * @return (AES256Key, Vec<u8>) - AES key with IV and HMAC key
 */
pub fn derive_keys_from_session_key_and_iv(k: &[u8], iv: &[u8]) -> (AES256Key, Vec<u8>) {
    // Verify input key sizes
    assert_eq!(k.len(), 32, "Session key must be 32 bytes");
    assert_eq!(iv.len(), 16, "IV must be 16 bytes");

    // Create HKDF instance with the session key
    let hk = Hkdf::<Sha256>::new(None, k);

    // Allocate memory for the derived keys
    let mut aes_key = [0u8; 32];
    let mut hmac_key = [0u8; 32];

    // Derive keys for different purposes using different info parameters
    hk.expand(b"aes encryption", &mut aes_key).expect("AES key derivation failed");
    hk.expand(b"hmac signing", &mut hmac_key).expect("HMAC key derivation failed");

    // Create AES key structure with the derived key and provided IV
    let aes = AES256Key {
        key: aes_key.to_vec(),
        iv: iv.to_vec(),
    };

    (aes, hmac_key.to_vec())
}

/**
 * Encrypt a plaintext string using AES-256-CBC and return base64-encoded ciphertext
 * 
 * @param aes - The AES key and IV
 * @param plaintext - The text to encrypt
 * @return String - Base64-encoded encrypted data
 */
pub fn aes256_encrypt_to_base64(aes: &AES256Key, plaintext: &str) -> String {
    // Use AES-256 in CBC mode
    let cipher = Cipher::aes_256_cbc();
    
    // Perform the encryption
    let ciphertext = encrypt(cipher, &aes.key, Some(&aes.iv), plaintext.as_bytes())
        .expect("Encryption failed");

    // Encode the ciphertext as base64
    general_purpose::STANDARD.encode(&ciphertext)
}

/**
 * Decrypt a base64-encoded AES-256-CBC ciphertext
 * 
 * @param aes - The AES key and IV
 * @param base64_ciphertext - The base64-encoded encrypted data
 * @return String - The decrypted plaintext
 */
pub fn aes256_decrypt_from_base64(aes: &AES256Key, base64_ciphertext: &str) -> String {
    // Use AES-256 in CBC mode
    let cipher = Cipher::aes_256_cbc();
    
    // Decode the base64 ciphertext
    let ciphertext =
        general_purpose::STANDARD.decode(base64_ciphertext).expect("Failed to decode ciphertext");
    
    // Perform the decryption
    let plaintext =
        decrypt(cipher, &aes.key, Some(&aes.iv), &ciphertext).expect("Decryption failed");

    // Convert the decrypted bytes to a UTF-8 string
    String::from_utf8(plaintext).expect("Invalid UTF-8")
}

/**
 * Generate a new random AES-256 key and IV and return as a formatted string
 * 
 * @return String - Formatted string with base64-encoded key and IV
 */
pub fn generate_symmetric_key() -> String {
    // Generate a random AES key and IV
    let aes = AES256Key::generate();
    
    // Convert to base64 strings
    let (key_b64, iv_b64) = aes.save_to_base64();
    
    // Format as a string for storage or transmission
    format!("Key: {}, IV: {}", key_b64, iv_b64)
}

/**
 * Parse a formatted string containing base64-encoded key and IV
 * 
 * @param s - Formatted string in the format "Key: {base64_key}, IV: {base64_iv}"
 * @return AES256Key - The parsed AES key and IV
 */
pub fn load_from_base64_string(s: &str) -> AES256Key {
    // Split the string into parts
    let parts: Vec<&str> = s.split(", ").collect();
    
    // Extract and strip the prefixes
    let key_b64 = parts[0].strip_prefix("Key: ").expect("Failed to parse key");
    let iv_b64 = parts[1].strip_prefix("IV: ").expect("Failed to parse IV");

    // Load the key from the base64 strings
    AES256Key::load_from_base64(key_b64, iv_b64)
}

/**
 * Generate an HMAC-SHA256 signature for a message
 * 
 * Creates an authentication tag for a message using HMAC with SHA-256
 * to ensure data integrity and authenticity.
 * 
 * @param key - The secret key for HMAC calculation
 * @param message - The message to authenticate
 * @return Vec<u8> - The HMAC signature/tag
 */
pub fn hmac_sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    // Create a new HMAC instance with the provided key
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("Invalid HMAC key");
    
    // Update with the message data
    mac.update(message);
    
    // Finalize and return the HMAC tag
    mac.finalize().into_bytes().to_vec()
}

/// Verify an HMAC signature
pub fn hmac_verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("Invalid HMAC key");
    mac.update(message);
    mac.verify_slice(signature).is_ok()
}

/// Encrypt and sign a plaintext
pub fn encrypt_and_sign(aes: &AES256Key, plaintext: &str, hmac_key: &[u8]) -> (String, String) {
    let ciphertext_b64 = aes256_encrypt_to_base64(aes, plaintext);
    let signature = hmac_sign(hmac_key, ciphertext_b64.as_bytes());
    let signature_b64 = general_purpose::STANDARD.encode(signature);
    (ciphertext_b64, signature_b64)
}

/// Verify and decrypt a signed ciphertext
pub fn verify_and_decrypt(
    aes: &AES256Key,
    ciphertext_b64: &str,
    signature_b64: &str,
    hmac_key: &[u8],
) -> Option<String> {
    let signature = general_purpose::STANDARD.decode(signature_b64).ok()?;
    if !hmac_verify(hmac_key, ciphertext_b64.as_bytes(), &signature) {
        return None;
    }
    Some(aes256_decrypt_from_base64(aes, ciphertext_b64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let aes = AES256Key::generate();
        assert_eq!(aes.key.len(), 32);
        assert_eq!(aes.iv.len(), 16);
    }

    #[test]
    fn test_save_to_base64() {
        let aes = AES256Key::generate();
        let (key_b64, iv_b64) = aes.save_to_base64();
        assert_eq!(general_purpose::STANDARD.decode(&key_b64).unwrap().len(), 32);
        assert_eq!(general_purpose::STANDARD.decode(&iv_b64).unwrap().len(), 16);
    }

    #[test]
    fn test_load_from_base64() {
        let aes = AES256Key::generate();
        let (key_b64, iv_b64) = aes.save_to_base64();
        let loaded = AES256Key::load_from_base64(&key_b64, &iv_b64);
        assert_eq!(aes.key, loaded.key);
        assert_eq!(aes.iv, loaded.iv);
    }

    #[test]
    fn test_load_from_base64_string() {
        let aes = AES256Key::generate();
        let (key_b64, iv_b64) = aes.save_to_base64();
        let formatted = format!("Key: {}, IV: {}", key_b64, iv_b64);
        let loaded = load_from_base64_string(&formatted);
        assert_eq!(aes.key, loaded.key);
        assert_eq!(aes.iv, loaded.iv);
    }

    #[test]
    fn test_encryption_decryption() {
        let aes = AES256Key::generate();
        let plaintext = "Hello AES CBC";
        let encrypted = aes256_encrypt_to_base64(&aes, plaintext);
        let decrypted = aes256_decrypt_from_base64(&aes, &encrypted);
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_hmac_sign_and_verify() {
        let key = b"test_hmac_key";
        let message = b"my message";
        let signature = hmac_sign(key, message);
        assert!(hmac_verify(key, message, &signature));
        assert!(!hmac_verify(key, b"wrong message", &signature));
    }

    #[test]
    fn test_encrypt_and_sign() {
        let aes = AES256Key::generate();
        let hmac_key = b"very_secret_hmac_key_32_bytes!!";

        let plaintext = "Sensitive message";
        let (cipher_b64, sig_b64) = encrypt_and_sign(&aes, plaintext, hmac_key);
        let result = verify_and_decrypt(&aes, &cipher_b64, &sig_b64, hmac_key);

        assert_eq!(Some(plaintext.to_string()), result);

        // Tamper with signature
        let bad_sig = general_purpose::STANDARD.encode(vec![0u8; 32]);
        let result = verify_and_decrypt(&aes, &cipher_b64, &bad_sig, hmac_key);
        assert!(result.is_none());
    }

    #[test]
    fn test_generate_symmetric_key() {
        let output = generate_symmetric_key();
        assert!(output.contains("Key: ") && output.contains("IV: "));
    }

    #[test]
    fn test_load_from_base64_string_invalid() {
        let bad_str = "Key: not_base64, IV: still_not_base64";
        let result = std::panic::catch_unwind(|| load_from_base64_string(bad_str));
        assert!(result.is_err());
    }
}
 