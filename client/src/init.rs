/**
 * Initialization Module
 * 
 * This module handles the initial setup of the client, including key pair generation,
 * registration with the Certificate Authority (CA), and first-time setup procedures.
 */

use reqwest::Client;                                   // HTTP client for API calls
use serde::{Deserialize, Serialize};                   // JSON serialization/deserialization
use ciphering::rsa::{encrypt_to_base64, sign_to_base64, RSAKeyPair}; // RSA operations
use std::{fs, path::Path};                             // File system operations
use ciphering::rsa::{read_public_key_from_file};       // RSA key loading
use ciphering::ecc_el_gammal::{save_keypair_to_pem, generate_keypair}; // ECC operations
use serde_json::Value;                                 // JSON value manipulation

/**
 * Generate and save an RSA key pair for secure communication
 * 
 * Creates a 2048-bit RSA key pair and saves both the private and public keys
 * to PEM files in the data directory.
 *
 * @return Result<(), Box<dyn std::error::Error>> - Success or an error
 */
fn generate_rsa_keypair_and_save() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new 2048-bit RSA key pair
    let keypair = RSAKeyPair::generate(2048);
    
    // Save the keys to PEM files in the data directory
    keypair.save_to_files("../data/myself/RSA_private_key.pem", "../data/myself/RSA_public_key.pem");
    
    print!("RSA keypair generated and saved to files.\n");
    Ok(())
}

/**
 * Generate and save an ECC key pair for secure communication
 * 
 * Creates an Elliptic Curve Cryptography key pair (using the k256/secp256k1 curve)
 * and saves both the private and public keys to PEM files in the data directory.
 *
 * @return Result<(), Box<dyn std::error::Error>> - Success or an error
 */
fn generate_ecc_keypair_and_save() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new ECC key pair
    let (sk, pk) = generate_keypair();
    
    // Save the keys to PEM files in the data directory
    let _ = save_keypair_to_pem(&sk, &pk, "../data/myself/ECC_private_key.pem", "../data/myself/ECC_public_key.pem");
    
    print!("ECC keypair generated and saved to files.\n");
    Ok(())
}


/**
 * Represents a registration message sent to the Certificate Authority
 * 
 * Contains the user's identifier, public keys (both RSA and ECC),
 * and IP address for client registration with the CA.
 */
#[derive(Deserialize, Serialize, Debug)]
struct MessageRegister {
    uid: String,    // User identifier
    pk_rsa: String, // RSA public key in PEM format
    pk_ecc: String, // ECC public key in PEM format
    ip: String,     // Client's public IP address
}

/**
 * Represents an encrypted message with signature
 * 
 * Used to securely transmit encrypted data along with
 * a digital signature for authentication.
 */
#[derive(Serialize, Deserialize)]
struct Cipher {
    c: String, // Encrypted message content (concatenated parts)
    t: String, // Digital signature for verification
}

/**
 * Split a string into N approximately equal parts
 * 
 * This function is used to divide large messages into smaller chunks
 * that can be encrypted separately, working around RSA size limitations.
 *
 * @param input - The string to split
 * @param parts - The number of parts to split into
 * @return Vec<String> - Vector containing the split parts
 */
fn split_equally(input: &str, parts: usize) -> Vec<String> {
    // Calculate the length of each part (rounded up)
    let len = input.len();
    let part_size = (len + parts - 1) / parts;
    
    // Split the input into chunks and convert each chunk to a String
    input
        .as_bytes()
        .chunks(part_size)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect()
}







/**
 * Register a new client with the Certificate Authority (CA) server
 *
 * This function handles the first-time registration process, including:
 * - Generating RSA and ECC key pairs
 * - Encrypting the registration message for the CA
 * - Submitting credentials to the CA server
 * - Creating an installation marker upon successful registration
 *
 * @param uid - User identifier for registration
 * @param ip - Client's public IP address
 * @return Result<(), Box<dyn std::error::Error>> - Success or an error
 */
pub async fn register_on_first_install(uid: &str, ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let marker_file = "../.installed_marker";

    // Skip registration if the client is already registered
    if Path::new(marker_file).exists() {
        println!("Already registered. Skipping registration.");
        return Ok(());
    }

    // Generate cryptographic key pairs for secure communication
    let _ = generate_rsa_keypair_and_save()?;
    let _ = generate_ecc_keypair_and_save()?;

    // Load the generated RSA keys for signing the registration message
    let keys = RSAKeyPair::load_from_files(
        "../data/myself/RSA_private_key.pem",
        "../data/myself/RSA_public_key.pem",
    );

    // Load the Certificate Authority's public key for encrypting the registration message
    let server_pub_key = read_public_key_from_file("../data/myself/CA_rsa_pub.pem");

    // Get reference to the client's private key for signing
    let private_key = &keys.private_key;
    //let public_key = &keys.public_key;

    // Load the public key PEM contents for registration
    let pk_rsa = fs::read_to_string("../data/myself/RSA_public_key.pem")?;
    let pk_ecc = fs::read_to_string("../data/myself/ECC_public_key.pem")?;

    // Display the public keys for verification
    println!("Public RSA Key: {}", pk_rsa);
    println!("Public ECC Key: {}", pk_ecc);

    // Create the registration message with user ID, IP, and public keys
    let message = MessageRegister {
        uid: uid.to_string(),
        ip: ip.to_string(),
        pk_rsa: pk_rsa.to_string(),
        pk_ecc: pk_ecc.to_string(),
    };

    // Convert the registration message to a JSON string
    let json_message = serde_json::to_string(&message)?;

    // Split and encrypt the message in 4 chunks to overcome RSA size limitations
    // (RSA can only encrypt data smaller than the key size)
    let parts = split_equally(&json_message, 4);
    let mut encrypted_parts = Vec::new();
    for part in parts {
        // Encrypt each part with the CA's public key for confidentiality
        let encrypted = encrypt_to_base64(&server_pub_key, &part);
        encrypted_parts.push(encrypted);
    }

    // Join encrypted parts with delimiter for transmission
    let encrypted_combined = encrypted_parts.join("::");
    
    // Sign the original JSON message with our private key for authentication
    let signature = sign_to_base64(private_key, &json_message);

    // Create the final payload containing encrypted data and signature
    let cipher_payload = Cipher {
        c: encrypted_combined,
        t: signature,
    };

    // Send the registration request to the Certificate Authority server
    let client = Client::new();
    let res = client
        .post("http://217.129.170.191:3000/hello-i-was-born")
        .json(&cipher_payload)
        .send()
        .await?;

    // Get the server's response
    let body = res.text().await?;

    // Parse and handle error responses from the server
    if let Ok(json) = serde_json::from_str::<Value>(&body) {
        if let Some(error_msg) = json.get("error").and_then(|v| v.as_str()) {
            if error_msg.contains("AlreadyExists") {
                // Handle the case where the user ID is already registered
                return Err("❌ Error: UID already exists.".into());
            } else {
                // Handle other server errors
                return Err(format!("❌ Error: {}", error_msg).into());
            }
        }
    }

    // Display the server's response for confirmation
    println!("Server response: {}", body);

    // Create a marker file indicating successful registration
    // This file also stores the user ID for future reference
    fs::write(marker_file, uid)?;

    Ok(())
}
