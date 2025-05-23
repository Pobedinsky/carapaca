/**
 * Certificate Authority (CA) Client Module
 * 
 * This module handles communication with the Certificate Authority server,
 * including key verification, IP address updates, and secure message exchange.
 * It implements the client side of the Public Key Infrastructure (PKI).
 */

use std::fs;                                 // File system operations
use std::path::Path;                         // Path handling
use aes_gcm::{Aes256Gcm, Nonce};            // AES-GCM encryption components

use serde::{Deserialize, Serialize};         // JSON serialization/deserialization
use serde_json::to_string;                   // JSON string conversion

use ciphering::rsa::sign_to_base64;          // RSA signature generation
use ciphering::rsa::{verify_signature_from_base64}; // RSA signature verification

use generic_array::GenericArray;             // Generic array for cryptographic operations
use reqwest::Client;                         // HTTP client

use rand::Rng;                               // Random number generation
use base64::{engine::general_purpose, Engine as _}; // Base64 encoding/decoding
use openssl::pkey::PKey;                     // OpenSSL key handling
use ciphering::rsa::encrypt_to_base64;       // RSA encryption

/**
 * Represents a user in the system with their cryptographic keys and IP
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub uid: String,    // User identifier
    pub pk_rsa: String, // RSA public key in PEM format
    pub pk_ecc: String, // ECC public key in PEM format
    pub ip: String,     // User's IP address
}

/**
 * Response from the server containing user information and authentication
 */
#[derive(Deserialize, Debug)]
struct ServerResponse {
    nonce: String,      // Nonce for preventing replay attacks
    signature: String,  // Server's signature to verify authenticity
    user: User,         // User information
}

/**
 * Generate a cryptographically secure nonce (number used once)
 * 
 * Creates a random 12-byte nonce suitable for use with AES-GCM encryption
 * and returns it as a base64-encoded string.
 *
 * @return String - The base64-encoded nonce
 */
fn generate_nonce() -> String {
    // Create a cryptographically secure random number generator
    let mut rng = rand::thread_rng();
    
    // Create a buffer for the nonce bytes
    let mut nonce_bytes = [0u8; 12];
    
    // Fill the buffer with random bytes
    rng.fill(&mut nonce_bytes);

    // Convert to the proper GenericArray format required by AES-GCM
    let nonce: &GenericArray<u8, <Aes256Gcm as aead::AeadCore>::NonceSize> = Nonce::from_slice(&nonce_bytes);
    
    // Encode the nonce bytes as a base64 string and return
    general_purpose::STANDARD.encode(nonce)
}



/**
 * Secure message structure for encrypted communication with the CA server
 * 
 * Contains the encrypted message, digital signature, and nonce for secure
 * and authenticated communication.
 */
#[derive(Serialize, Deserialize, Debug)]
struct SecureMessage {
    c: String,      // Encrypted message (base64)
    t: String,      // Signature (base64) for authentication
    nonce: String,  // Nonce (plaintext, used for response binding)
}

/**
 * Payload structure for IP address updates
 * 
 * Contains the user ID and new IP address to be updated on the CA server.
 */
#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    uid: String,    // User identifier
    ip: String,     // New IP address
}

/**
 * Secure response from the CA server
 * 
 * Contains the encrypted message, nonce for verification, and
 * signature for authentication.
 */
#[derive(Deserialize, Debug)]
struct SecureResponseData {
    message: String, // Response message
    nonce: String,   // Nonce (for verification)
    t: String,       // Signature for authentication
}


/**
 * Update the client's IP address on the CA server
 * 
 * This function securely sends the client's new IP address to the CA server
 * using encrypted and signed messages for authentication and confidentiality.
 *
 * @param uid - User identifier
 * @param new_ip - New IP address to register
 * @return Result<(), Box<dyn std::error::Error>> - Success or error
 */
pub async fn update_ip_to_server(uid: &str, new_ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load the client's private key for signing
    let priv_key_pem = fs::read("../data/myself/RSA_private_key.pem")?;
    let priv_key = PKey::private_key_from_pem(&priv_key_pem)?;

    // Load the CA server's public key for encryption
    let server_pub_pem = fs::read("../data/myself/CA_rsa_pub.pem")?;
    let server_pub_key = PKey::public_key_from_pem(&server_pub_pem)?;

    // Create the payload with user ID and new IP
    let payload = Payload {
        uid: uid.to_string(),
        ip: new_ip.to_string(),
    };

    // Convert payload to JSON and generate a nonce
    let json_payload = serde_json::to_string(&payload)?;
    let nonce = generate_nonce();

    // Combine payload and nonce
    let message = format!("{}::{}", json_payload, nonce);

    // Encrypt the message with the server's public key
    let encrypted = encrypt_to_base64(&server_pub_key, &message);

    // Sign the message with the client's private key
    let signature = sign_to_base64(&priv_key, &message);

    // Create the secure message
    let secure_msg = SecureMessage {
        c: encrypted,
        t: signature,
        nonce: nonce.clone(),
    };

    // Create HTTP client and send the secure message to the CA server
    let client = Client::new();
    let res = client
        .post("http://217.129.170.191:3000/wassap-im-ready")
        .json(&secure_msg)
        .send()
        .await?;

    // Check if the server response was successful
    if !res.status().is_success() {
        eprintln!("❌ Server returned error: {}", res.status());
        return Ok(());
    }

    let response_data: SecureResponseData = res.json().await?;

    let returned_message = format!("{}::{}", response_data.message, response_data.nonce);

    // Verify response signature
    let is_valid = verify_signature_from_base64(&server_pub_key, &returned_message, &response_data.t);

    if is_valid {
        println!("✅ IP successfully updated to {} and verified", response_data.message);
    } else {
        eprintln!("❌ Failed to verify server response signature");
    }

    Ok(())
}















/**
 * Verify and store public keys and IP address for a user from the CA server
 * 
 * This function retrieves, verifies, and stores the public keys and IP address
 * of another user from the Certificate Authority, ensuring their authenticity
 * through digital signature verification.
 *
 * @param uid - User identifier to retrieve keys for
 * @return Result<(), Box<dyn std::error::Error>> - Success or error
 */
pub async fn verify_and_store_keys_from_server(uid: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Define file paths for storing the user's keys and IP
    let rsa_path = format!("../data/keys/clients/{}_rsa.pem", uid);
    let ecc_path = format!("../data/keys/clients/{}_ecc.pem", uid);
    let ip_path = format!("../data/keys/clients/{}_ip.txt", uid);

    // Skip retrieval if keys already exist locally
    if Path::new(&rsa_path).exists() && Path::new(&ecc_path).exists() && Path::new(&ip_path).exists(){
        println!("✅ Keys already exist for UID '{}'", uid);
        return Ok(());
    }

    // Generate a nonce for this request to prevent replay attacks
    let nonce = generate_nonce();

    // Request user data from the CA server
    let url = format!("http://217.129.170.191:3000/holy-bible/{}?nonce={}", uid, nonce);
    let response = reqwest::get(&url).await?;
    
    // Check if the server responded successfully
    if !response.status().is_success() {
        eprintln!("❌ Server returned error: {}", response.status());
        return Ok(());
    }

    // Parse the server response
    let data: ServerResponse = response.json().await?;
    
    // Reconstruct the signed message (user data + nonce)
    let user_json = to_string(&data.user)?;
    let signed_msg = format!("{}{}", user_json, data.nonce);

    // Load the CA server's public key for signature verification
    let server_pub_pem = fs::read("../data/myself/CA_rsa_pub.pem")?;
    let server_pub_key = openssl::pkey::PKey::public_key_from_pem(&server_pub_pem)?;

    // Verify the digital signature on the user data
    let is_valid = verify_signature_from_base64(&server_pub_key, &signed_msg, &data.signature);

    // Process based on signature verification result
    if is_valid {
        println!("✅ Signature is valid. Saving keys.");
        
        // Create directory structure if needed
        fs::create_dir_all("../data/keys")?;
        fs::create_dir_all("../data/keys/clients")?;
        
        // Save RSA and ECC public keys to files
        fs::write(&rsa_path, &data.user.pk_rsa)?;
        fs::write(&ecc_path, &data.user.pk_ecc)?;
        println!("✅ Keys saved to {} and {}", rsa_path, ecc_path);
        
        // Save IP address to file
        fs::write(&ip_path, &data.user.ip)?;
        println!("✅ IP saved to {}", ip_path);
    } else {
        // Reject keys if signature verification failed
        eprintln!("❌ Signature is invalid. Rejecting keys.");
    }

    Ok(())
}
