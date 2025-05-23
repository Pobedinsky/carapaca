/**
 * RSA Cryptographic Operations Module
 * 
 * This module provides RSA encryption, decryption, signing, and verification
 * functions using the OpenSSL library. It handles key generation, file storage,
 * and common cryptographic operations needed for the secure communication system.
 */

use openssl::rsa::{Padding, Rsa};                // RSA implementation from OpenSSL
use openssl::pkey::{PKey, Private, Public};      // Key management
use openssl::sign::{Signer, Verifier};           // Digital signature operations
use openssl::hash::MessageDigest;                // Hashing algorithms
use std::fs::{read, write};                      // File I/O
use base64::{engine::general_purpose, Engine as _}; // Base64 encoding/decoding

/**
 * Represents an RSA key pair with both private and public components
 */
pub struct RSAKeyPair {
    pub private_key: PKey<Private>,   // The private key component
    pub public_key: PKey<Public>,     // The public key component
}

impl RSAKeyPair {
    /**
     * Generate a new RSA key pair with the specified bit length
     * 
     * @param bits - Key size in bits (typically 2048 or 4096 for security)
     * @return RSAKeyPair - A new key pair instance
     */
    pub fn generate(bits: u32) -> RSAKeyPair {
        // Generate the RSA key pair with the specified bit length
        let rsa = Rsa::generate(bits).expect("Failed to generate RSA key");
        let private_key = PKey::from_rsa(rsa).expect("Failed to convert to PKey");

        // Extract the public key from the private key
        let public_key_der = private_key.rsa().unwrap().public_key_to_der().unwrap();
        let public_key = PKey::public_key_from_der(&public_key_der).unwrap();

        RSAKeyPair { private_key, public_key }
    }

    /**
     * Save both private and public keys to PEM files
     * 
     * @param private_path - Filesystem path for storing the private key
     * @param public_path - Filesystem path for storing the public key
     */
    pub fn save_to_files(&self, private_path: &str, public_path: &str) {
        // Convert keys to PEM format
        let private_pem = self.private_key.private_key_to_pem_pkcs8().unwrap();
        let public_pem = self.public_key.public_key_to_pem().unwrap();
        
        // Write keys to files
        write(private_path, private_pem).expect("Failed to write private key");
        write(public_path, public_pem).expect("Failed to write public key");
    }

    /**
     * Load an RSA key pair from existing PEM files
     * 
     * @param private_path - Filesystem path to the private key PEM file
     * @param public_path - Filesystem path to the public key PEM file
     * @return RSAKeyPair - The loaded key pair
     */
    pub fn load_from_files(private_path: &str, public_path: &str) -> RSAKeyPair {
        // Read the key files
        let private_bytes = read(private_path).expect("Failed to read private key file");
        let public_bytes = read(public_path).expect("Failed to read public key file");
        
        // Parse the keys from PEM format
        let private_key = PKey::private_key_from_pem(&private_bytes).unwrap();
        let public_key = PKey::public_key_from_pem(&public_bytes).unwrap();
        
        RSAKeyPair { private_key, public_key }
    }
}

/**
 * Read a public RSA key from a PEM file
 * 
 * @param path - Path to the public key PEM file
 * @return PKey<Public> - The parsed public key
 */
pub fn read_public_key_from_file(path: &str) -> PKey<Public> {
    // Read the key file contents
    let public_bytes = read(path).expect("Failed to read public key file");
    
    // Parse the key from PEM format
    PKey::public_key_from_pem(&public_bytes).expect("Failed to parse public key")
}

/**
 * Encrypt a plaintext string using RSA and return base64-encoded ciphertext
 * 
 * @param public_key - The recipient's public key
 * @param plaintext - The message to encrypt
 * @return String - Base64-encoded encrypted data
 */
pub fn encrypt_to_base64(public_key: &PKey<Public>, plaintext: &str) -> String {
    // Get the underlying RSA key implementation
    let rsa = public_key.rsa().unwrap();
    
    // Prepare a buffer for the encrypted data
    let mut buf = vec![0; rsa.size() as usize];
    
    // Encrypt the plaintext using PKCS1 padding
    let len = rsa.public_encrypt(plaintext.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
    
    // Truncate the buffer to the actual encrypted data size
    buf.truncate(len);
    
    // Encode the encrypted data to base64 and return
    general_purpose::STANDARD.encode(&buf)
}

/**
 * Decrypt a base64-encoded RSA ciphertext and return the plaintext string
 * 
 * @param private_key - The recipient's private key
 * @param base64_ciphertext - The base64-encoded encrypted data
 * @return String - The decrypted plaintext
 */
pub fn decrypt_from_base64(private_key: &PKey<Private>, base64_ciphertext: &str) -> String {
    // Get the underlying RSA key implementation
    let rsa = private_key.rsa().unwrap();
    
    // Decode the base64 ciphertext
    let ciphertext = general_purpose::STANDARD.decode(base64_ciphertext).unwrap();
    
    // Prepare a buffer for the decrypted data
    let mut buf = vec![0; rsa.size() as usize];
    
    // Decrypt the ciphertext using PKCS1 padding
    let len = rsa.private_decrypt(&ciphertext, &mut buf, Padding::PKCS1).unwrap();
    
    // Truncate the buffer to the actual decrypted data size
    buf.truncate(len);
    
    // Convert the decrypted bytes to a UTF-8 string
    String::from_utf8(buf).unwrap()
}

/**
 * Sign a message using RSA and return the base64-encoded signature
 * 
 * @param private_key - The signer's private key
 * @param message - The message to sign
 * @return String - Base64-encoded digital signature
 */
pub fn sign_to_base64(private_key: &PKey<Private>, message: &str) -> String {
    // Create a new signer with SHA-256 hash algorithm
    let mut signer = Signer::new(MessageDigest::sha256(), private_key).unwrap();
    
    // Update the signer with the message data
    signer.update(message.as_bytes()).unwrap();
    
    // Generate the signature
    let signature = signer.sign_to_vec().unwrap();
    
    // Encode the signature to base64 and return
    general_purpose::STANDARD.encode(&signature)
}

/**
 * Verify a base64-encoded RSA signature against a message
 * 
 * @param public_key - The signer's public key
 * @param message - The message that was signed
 * @param base64_signature - The base64-encoded signature to verify
 * @return bool - True if the signature is valid, false otherwise
 */
pub fn verify_signature_from_base64(public_key: &PKey<Public>, message: &str, base64_signature: &str) -> bool {
    // Decode the base64 signature
    let signature = general_purpose::STANDARD.decode(base64_signature).unwrap();
    
    // Create a new verifier with SHA-256 hash algorithm
    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
    
    // Update the verifier with the message data
    verifier.update(message.as_bytes()).unwrap();
    
    // Verify the signature, returning false if any errors occur
    verifier.verify(&signature).unwrap_or(false)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_base64() {
        let keypair = RSAKeyPair::generate(2048);
        let message = "Confidential message";

        let encrypted = encrypt_to_base64(&keypair.public_key, message);
        let decrypted = decrypt_from_base64(&keypair.private_key, &encrypted);

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_sign_verify_base64() {
        let keypair = RSAKeyPair::generate(2048);
        let message = "Data to be signed";

        let signature = sign_to_base64(&keypair.private_key, message);
        let is_valid = verify_signature_from_base64(&keypair.public_key, message, &signature);

        assert!(is_valid);
    }

    #[test]
    fn test_signature_fails_on_modified_message_base64() {
        let keypair = RSAKeyPair::generate(2048);
        let original_message = "Original message";
        let modified_message = "Tampered message";

        let signature = sign_to_base64(&keypair.private_key, original_message);
        let is_valid = verify_signature_from_base64(&keypair.public_key, modified_message, &signature);

        assert!(!is_valid);
    }

    #[test]
    fn test_load_and_save_keys_base64() {
        let keypair = RSAKeyPair::generate(2048);
        keypair.save_to_files("private.pem", "public.pem");

        let loaded_keypair = RSAKeyPair::load_from_files("private.pem", "public.pem");

        let message = "Message for loaded keys";
        let encrypted = encrypt_to_base64(&loaded_keypair.public_key, message);
        let decrypted = decrypt_from_base64(&loaded_keypair.private_key, &encrypted);

        assert_eq!(message, decrypted);
    }
}
