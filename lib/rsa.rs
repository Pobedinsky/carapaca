use openssl::rsa::{Padding, Rsa};
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use std::fs::{read, write};
use base64::{engine::general_purpose, Engine as _};


pub struct RSAKeyPair {
    pub private_key: PKey<Private>,
    pub public_key: PKey<Public>,
}

impl RSAKeyPair {
    /// Generate a new RSA keypair
    pub fn generate(bits: u32) -> RSAKeyPair {
        let rsa = Rsa::generate(bits).expect("Failed to generate RSA key");
        let private_key = PKey::from_rsa(rsa).expect("Failed to convert to PKey");

        // Extract the public key using public_key_to_der and create the PKey<Public>
        let public_key_der = private_key.rsa().unwrap().public_key_to_der().unwrap();
        let public_key = PKey::public_key_from_der(&public_key_der).unwrap();

        RSAKeyPair { private_key, public_key }
    }

    /// Save private and public keys to specified PEM files
    pub fn save_to_files(&self, private_path: &str, public_path: &str) {
        let private_pem = self.private_key.private_key_to_pem_pkcs8().unwrap();
        let public_pem = self.public_key.public_key_to_pem().unwrap();
        write(private_path, private_pem).expect("Failed to write private key");
        write(public_path, public_pem).expect("Failed to write public key");
    }

    /// Load keypair from existing PEM files
    pub fn load_from_files(private_path: &str, public_path: &str) -> RSAKeyPair {
        let private_bytes = read(private_path).expect("Failed to read private key file");
        let public_bytes = read(public_path).expect("Failed to read public key file");
        let private_key = PKey::private_key_from_pem(&private_bytes).unwrap();
        let public_key = PKey::public_key_from_pem(&public_bytes).unwrap();
        RSAKeyPair { private_key, public_key }
    }
}

pub fn read_public_key_from_file(path: &str) -> PKey<Public> {
    let public_bytes = read(path).expect("Failed to read public key file");
    PKey::public_key_from_pem(&public_bytes).expect("Failed to parse public key")
}

/// Encrypt a plaintext string and return base64-encoded ciphertext
pub fn encrypt_to_base64(public_key: &PKey<Public>, plaintext: &str) -> String {
    let rsa = public_key.rsa().unwrap();
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa.public_encrypt(plaintext.as_bytes(), &mut buf, Padding::PKCS1).unwrap();
    buf.truncate(len);
    general_purpose::STANDARD.encode(&buf)
}

/// Decrypt a base64-encoded ciphertext and return the plaintext string
pub fn decrypt_from_base64(private_key: &PKey<Private>, base64_ciphertext: &str) -> String {
    let rsa = private_key.rsa().unwrap();
    let ciphertext = general_purpose::STANDARD.decode(base64_ciphertext).unwrap();
    let mut buf = vec![0; rsa.size() as usize];
    let len = rsa.private_decrypt(&ciphertext, &mut buf, Padding::PKCS1).unwrap();
    buf.truncate(len);
    String::from_utf8(buf).unwrap()
}

/// Sign a message and return base64-encoded signature
pub fn sign_to_base64(private_key: &PKey<Private>, message: &str) -> String {
    let mut signer = Signer::new(MessageDigest::sha256(), private_key).unwrap();
    signer.update(message.as_bytes()).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    general_purpose::STANDARD.encode(&signature)
}

/// Verify a base64-encoded signature against a message
pub fn verify_signature_from_base64(public_key: &PKey<Public>, message: &str, base64_signature: &str) -> bool {
    let signature = general_purpose::STANDARD.decode(base64_signature).unwrap();
    let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
    verifier.update(message.as_bytes()).unwrap();
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
