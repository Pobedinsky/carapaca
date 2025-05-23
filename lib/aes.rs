use openssl::symm::{encrypt, decrypt, Cipher};
use rand::{RngCore, rngs::OsRng};
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use hkdf::Hkdf;

pub struct AES256Key {
    pub key: Vec<u8>, // 32 bytes
    pub iv: Vec<u8>,  // 16 bytes
}

impl AES256Key {
    /// Generate a random AES256 key and IV
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        let mut iv = vec![0u8; 16];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut iv);
        AES256Key { key, iv }
    }

    /// Save the key and IV to base64-encoded strings
    pub fn save_to_base64(&self) -> (String, String) {
        (
            general_purpose::STANDARD.encode(&self.key),
            general_purpose::STANDARD.encode(&self.iv),
        )
    }

    /// Load key and IV from base64-encoded strings
    pub fn load_from_base64(key_b64: &str, iv_b64: &str) -> Self {
        let key = general_purpose::STANDARD.decode(key_b64).expect("Failed to decode key");
        let iv = general_purpose::STANDARD.decode(iv_b64).expect("Failed to decode IV");
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 16);
        AES256Key { key, iv }
    }
}

pub fn derive_keys_from_session_key_and_iv(k: &[u8], iv: &[u8]) -> (AES256Key, Vec<u8>) {
    assert_eq!(k.len(), 32, "Chave de sessão deve ter 32 bytes");
    assert_eq!(iv.len(), 16, "IV deve ter 16 bytes");

    let hk = Hkdf::<Sha256>::new(None, k);

    let mut aes_key = [0u8; 32];
    let mut hmac_key = [0u8; 32];

    hk.expand(b"aes encryption", &mut aes_key).expect("Falha na derivação AES");
    hk.expand(b"hmac signing", &mut hmac_key).expect("Falha na derivação HMAC");

    let aes = AES256Key {
        key: aes_key.to_vec(),
        iv: iv.to_vec(),
    };

    (aes, hmac_key.to_vec())
}

/// Encrypt a plaintext string to base64-encoded ciphertext
pub fn aes256_encrypt_to_base64(aes: &AES256Key, plaintext: &str) -> String {
    let cipher = Cipher::aes_256_cbc();
    let ciphertext = encrypt(cipher, &aes.key, Some(&aes.iv), plaintext.as_bytes())
        .expect("Encryption failed");

    general_purpose::STANDARD.encode(&ciphertext)
}

/// Decrypt a base64-encoded ciphertext string
pub fn aes256_decrypt_from_base64(aes: &AES256Key, base64_ciphertext: &str) -> String {
    let cipher = Cipher::aes_256_cbc();
    let ciphertext =
        general_purpose::STANDARD.decode(base64_ciphertext).expect("Failed to decode ciphertext");
    let plaintext =
        decrypt(cipher, &aes.key, Some(&aes.iv), &ciphertext).expect("Decryption failed");

    String::from_utf8(plaintext).expect("Invalid UTF-8")
}

pub fn generate_symmetric_key() -> String {
    let aes = AES256Key::generate();
    let (key_b64, iv_b64) = aes.save_to_base64();
    format!("Key: {}, IV: {}", key_b64, iv_b64)
}

pub fn load_from_base64_string(s: &str) -> AES256Key {
    let parts: Vec<&str> = s.split(", ").collect();
    let key_b64 = parts[0].strip_prefix("Key: ").expect("Failed to parse key");
    let iv_b64 = parts[1].strip_prefix("IV: ").expect("Failed to parse IV");

    AES256Key::load_from_base64(key_b64, iv_b64)
}

/// Generate an HMAC signature for a message
pub fn hmac_sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("Invalid HMAC key");
    mac.update(message);
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
 