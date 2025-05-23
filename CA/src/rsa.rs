// RSA Cryptography Implementation Module
// This file provides RSA encryption, decryption, signing and verification operations
// It also handles PEM file operations for storing and retrieving keys
use openssl::rsa::{Padding, Rsa};
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use std::fs::{read, write};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

// Structure to hold an RSA key pair (private and public keys)
pub struct RSAKeyPair {
    pub private_key: PKey<Private>,
    pub public_key: PKey<Public>,
}

impl RSAKeyPair {
    /// Generate a new RSA keypair
    /// Arguments:
    /// * `bits` - The key size in bits (typically 2048 or 4096)
    pub fn generate(bits: u32) -> RSAKeyPair {
        let rsa = Rsa::generate(bits).expect("Failed to generate RSA key");
        let private_key = PKey::from_rsa(rsa).expect("Failed to convert to PKey");

        // Extract the public key using public_key_to_der and create the PKey<Public>
        let public_key_der = private_key.rsa().unwrap().public_key_to_der().unwrap();
        let public_key = PKey::public_key_from_der(&public_key_der).unwrap();

        RSAKeyPair { private_key, public_key }
    }

    /// Save private and public keys to specified PEM files
    /// Arguments:
    /// * `private_path` - Path to the file where the private key will be saved
    /// * `public_path` - Path to the file where the public key will be saved
    pub fn save_to_files(&self, private_path: &str, public_path: &str) {
        let private_pem = self.private_key.private_key_to_pem_pkcs8().unwrap();
        let public_pem = self.public_key.public_key_to_pem().unwrap();
        write(private_path, private_pem).expect("Failed to write private key");
        write(public_path, public_pem).expect("Failed to write public key");
    }

    /// Load keypair from existing PEM files
    /// Arguments:
    /// * `private_path` - Path to the file from which the private key will be loaded
    /// * `public_path` - Path to the file from which the public key will be loaded
    /// Returns: RSAKeyPair - The loaded RSA key pair
    pub fn load_from_files(private_path: &str, public_path: &str) -> RSAKeyPair {
        let private_bytes = read(private_path).expect("Failed to read private key file");
        let public_bytes = read(public_path).expect("Failed to read public key file");
        let private_key = PKey::private_key_from_pem(&private_bytes).unwrap();
        let public_key = PKey::public_key_from_pem(&public_bytes).unwrap();
        RSAKeyPair { private_key, public_key }
    }
}

/// Encrypt a plaintext string and return base64-encoded ciphertext
/// Arguments:
/// * `public_key` - The public key used for encryption
/// * `plaintext` - The plaintext string to be encrypted
/// Returns: String - The base64-encoded ciphertext
pub fn encrypt_to_base64(public_key: &PKey<Public>, plaintext: &str) -> String {
    let rsa = public_key.rsa().unwrap();
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa.public_encrypt(plaintext.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
    buf.truncate(len);
    STANDARD.encode(&buf)

}

/// Decrypt a base64-encoded ciphertext and return the plaintext string
/// Arguments:
/// * `private_key` - The private key used for decryption
/// * `base64_ciphertext` - The base64-encoded ciphertext to be decrypted
/// Returns: Result<String, String> - The decrypted plaintext string, or an error message
pub fn decrypt_from_base64(private_key: &PKey<Private>, base64_ciphertext: &str) -> Result<String, String> {
    let rsa = private_key.rsa().map_err(|e| e.to_string())?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(base64_ciphertext)
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa
        .private_decrypt(&ciphertext, &mut buf, Padding::PKCS1)
        .map_err(|e| e.to_string())?;
    buf.truncate(len);
    String::from_utf8(buf).map_err(|e| e.to_string())
}


/// Sign a message and return base64-encoded signature
/// Arguments:
/// * `private_key` - The private key used for signing
/// * `message` - The message string to be signed
/// Returns: String - The base64-encoded signature
pub fn sign_to_base64(private_key: &PKey<Private>, message: &str) -> String {
    let mut signer = Signer::new(MessageDigest::sha256(), private_key).unwrap();
    signer.update(message.as_bytes()).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    STANDARD.encode(&signature)

}

/// Verify a base64-encoded signature against a message
/// Arguments:
/// * `public_key` - The public key used for verification
/// * `message` - The message string whose signature is to be verified
/// * `base64_signature` - The base64-encoded signature to be verified
/// Returns: bool - True if the signature is valid, false otherwise
pub fn verify_signature_from_base64(public_key: &PKey<Public>, message: &str, base64_signature: &str) -> bool {
    let signature = STANDARD.decode(base64_signature).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
    verifier.update(message.as_bytes()).unwrap();
    verifier.verify(&signature).unwrap_or(false)
}