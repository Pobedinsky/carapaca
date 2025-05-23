/**
 * Server Communication Module
 * 
 * This module handles all communication between the client and the remote server,
 * including authentication, command execution, and secure message exchange using
 * various cryptographic protocols (RSA, ECC, AES).
 */

use reqwest::Client;                           // HTTP client for API calls
use serde::{Deserialize, Serialize};           // JSON serialization/deserialization
use ciphering::rsa::{
    encrypt_to_base64, sign_to_base64, decrypt_from_base64, 
    verify_signature_from_base64, read_public_key_from_file, RSAKeyPair
};                                             // RSA cryptographic operations
use std::fs::{File};                           // File handling
use std::io::Write;                            // Write trait for file operations
use ciphering::ecc_el_gammal::{
    sign_to_base64 as ecc_sign_to_base64, decrypt, encrypt,
    load_public_key_from_pem, load_private_key_from_pem, verify_signature
};                                             // ECC cryptographic operations
use k256::elliptic_curve::sec1::ToEncodedPoint; // Point encoding for ECC
use ciphering::aes::{
    load_from_base64_string, aes256_encrypt_to_base64, 
    aes256_decrypt_from_base64, verify_and_decrypt,
    derive_keys_from_session_key_and_iv, hmac_sign
};                                             // AES cryptographic operations
use base64::Engine;                            // Base64 encoding/decoding

/**
 * Represents a signature authentication request sent to the server
 */
#[derive(Serialize, Deserialize)]
struct SignatureRequest {
    uid: String,      // User identifier
    signature: String, // Base64-encoded digital signature
}

/**
 * Represents an encrypted message with signature
 */
#[derive(Serialize, Deserialize)]
struct Cipher {
    c: String, // Encrypted data (base64)
    t: String, // Signature/authentication tag (base64)
}

/**
 * Represents an encrypted message with signature and sender identity
 */
#[derive(Serialize, Deserialize)]
struct CipherWithUid {
    uid: String, // User identifier of the sender
    c: String,   // Encrypted data (base64)
    t: String,   // Signature/authentication tag (base64)
}

/**
 * Represents a server response containing an encrypted message
 */
#[derive(Deserialize)]
struct ResponseData {
    message: Cipher, // The encrypted message from the server
    status: String,  // Status of the request (success or error)
}

/**
 * Request a cryptographic nonce from the server
 * 
 * A nonce (number used once) is requested from the server to prevent replay attacks
 * during authentication. Each authentication attempt requires a fresh nonce.
 *
 * @param uid - The user identifier requesting the nonce
 * @param ip - The IP address of the server
 * @return Result<String, Box<dyn std::error::Error>> - The nonce string or an error
 */
pub async fn get_nonce(uid: &str, ip: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Create HTTP client and build request URL
    let client = Client::new();
    let url = format!("http://{}/get-nonce?uid={}", ip, uid);
    
    // Send GET request to server
    let response = client.get(&url).send().await?;
    let text = response.text().await?;

    println!("Response from GET /get-nonce: {}", text);

    // Parse the JSON response
    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    if parsed["status"] != "success" {
        return Err("Error obtaining nonce".into());
    }

    // Extract nonce from the message field
    let message = parsed["message"].as_str().unwrap_or("");
    let nonce = message.strip_prefix("Nonce: ").unwrap_or("").trim();

    // Validate the nonce is not empty
    if nonce.is_empty() {
        return Err("Empty nonce".into());
    }

    Ok(nonce.to_string())
}

/**
 * Send an RSA signature to the server for authentication
 * 
 * This function signs a message containing the user ID and nonce using the user's
 * RSA private key, then sends it to the server for verification. Upon successful
 * authentication, the server responds with an encrypted session key.
 *
 * @param uid - The user's identifier
 * @param nonce - The nonce received from the server
 * @param ip - The server's IP address
 * @param uid_bob - The recipient's identifier
 * @return Result<(), Box<dyn std::error::Error>> - Success or an error
 */
pub async fn send_signature_rsa(uid: &str, nonce: &str, ip: &str, uid_bob: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load RSA key pair from files
    let keys = RSAKeyPair::load_from_files(
        "../data/myself/RSA_private_key.pem",
        "../data/myself/RSA_public_key.pem",
    );
    let private_key = &keys.private_key;

    // Create message to sign (user ID + nonce)
    let message = format!("{}{}", uid, nonce);
    
    // Sign the message with the private key
    let signature = sign_to_base64(private_key, &message);

    // Prepare the authentication payload
    let payload = SignatureRequest {
        uid: uid.to_string(),
        signature,
    };

    // Send POST request to server with the signature
    let client = Client::new();
    let url = format!("http://{}/tuc-tuc", ip);
    let response = client.post(&url).json(&payload).send().await?;

    // Process the server response
    let res_text = response.text().await?;
    println!("Response from POST /tuc-tuc: {}", res_text);

    // Parse and validate the response
    let response: ResponseData = serde_json::from_str(&res_text)?;
    if response.status != "success" {
        return Err("Server returned error".into());
    }

    let cipher = response.message;
    let c = cipher.c;
    let t = cipher.t;

    let bob_pubkey_path = format!("../data/keys/clients/{}_rsa.pem", uid_bob);
    let bob_pubkey = read_public_key_from_file(&bob_pubkey_path);

    if !verify_signature_from_base64(&bob_pubkey, &c, &t) {
        return Err("Assinatura da chave de sessão inválida".into());
    }

    let session_key = decrypt_from_base64(private_key, &c);
    println!("Chave de sessão decifrada: {}", session_key);

    let session_path = format!("session_keys/{}_session_key.txt", uid_bob);
    let mut file = File::create(&session_path)?;
    file.write_all(session_key.as_bytes())?;
    println!("Chave de sessão guardada em {}", session_path);

    Ok(())
}


pub async fn send_signature_ecc(uid: &str, nonce: &str, ip: &str, uid_bob: &str) -> Result<(), Box<dyn std::error::Error>> {
    let sk = load_private_key_from_pem("../data/myself/ECC_private_key.pem".to_string());
    let pk = load_public_key_from_pem("../data/myself/ECC_public_key.pem".to_string());
    let pk_bob = load_public_key_from_pem(format!("../data/keys/clients/{}_ecc.pem", uid_bob).to_string());

    let message = format!("{}{}", uid, nonce);
    let signature = ecc_sign_to_base64(&sk, message.as_bytes()); // ⬅️ usa .as_bytes()

    let payload = SignatureRequest {
        uid: uid.to_string(),
        signature,
    };

    let client = Client::new();
    let url = format!("http://{}/tuc-tuc", ip);
    let response = client.post(&url).json(&payload).send().await?;

    let res_text = response.text().await?;
    println!("Resposta do POST /tuc-tuc: {}", res_text);


    let response: ResponseData = serde_json::from_str(&res_text)?;
    if response.status != "success" {
        return Err("Servidor retornou erro".into());
    }

    let cipher = response.message;
    let c = cipher.c;
    let t = cipher.t;

    // Verifica assinatura do servidor
    if !verify_signature(&pk_bob, c.as_bytes(), &t) {
        return Err("Assinatura inválida do servidor".into());
    }

    // Decifra a mensagem recebida
    let decrypted_bytes = decrypt(&sk, &c)?;
    let decrypted_str = String::from_utf8(decrypted_bytes.clone())
        .map_err(|_| "Mensagem decifrada não é UTF-8")?;

    // Esperado: "public_key_sec1_string::nonce"
    let parts: Vec<&str> = decrypted_str.splitn(2, "::").collect();
    if parts.len() != 2 {
        return Err("Formato da mensagem decifrada inválido".into());
    }            // Get the SEC1 representation of the local public key
            let encoded_point = pk.to_encoded_point(false); // uncompressed format
            let local_pk_str = encoded_point.to_string();

            // Verify the public key returned by the server matches our local one
            if parts[0] == local_pk_str {
                println!("🔐 Public key successfully confirmed by the server.");
            } else {
                println!("❌ Returned public key doesn't match local key!");
                return Err("Public key not confirmed".into());
            }

            Ok(())
        }


/**
 * Execute a command on the remote server with secure authentication and encryption
 * 
 * This function securely sends commands to the server using different encryption
 * methods (RSA, ECC, or hybrid with AES) based on the selected type.
 * It handles authentication, encryption, and signature verification for
 * secure communication.
 *
 * @param uid - The user's identifier
 * @param nonce - A cryptographic nonce for this session
 * @param ip - The server's IP address
 * @param typ - Encryption type ("RSA", "ECC", "RSA_AES", or "ECC_AES")
 * @param command - The command to execute on the server
 * @param uid_bob - The recipient's identifier
 * @return Result<String, Box<dyn std::error::Error>> - Command output or error
 */
pub async fn executer(uid: &str, nonce: &str, ip: &str, typ: &str, command: &str, uid_bob: &str) -> Result<String, Box<dyn std::error::Error>> {
    match typ {
        "RSA" => {
            // Load RSA key pair for authentication and decryption
            let keys = RSAKeyPair::load_from_files(
                "../data/myself/RSA_private_key.pem",
                "../data/myself/RSA_public_key.pem",
            );
            let private_key = &keys.private_key;

            // Load the session key established during authentication
            let session_key = std::fs::read_to_string(format!("session_keys/{}_session_key.txt", uid_bob))
                .expect("Failed to read session key");

            // Load recipient's public key for verification
            let bob_pubkey_path = format!("../data/keys/clients/{}_rsa.pem", uid_bob);
            let bob_pubkey = read_public_key_from_file(&bob_pubkey_path);

            // Create and encrypt user ID and nonce using recipient's public key
            let uid_nonce = format!("{}::{}", uid, nonce);
            let uid_nonce_ciphered = encrypt_to_base64(&bob_pubkey, &uid_nonce);

            // Parse the session key for AES encryption
            let session_key = load_from_base64_string(&session_key);

            // Create and encrypt command with nonce using session key
            let command_nonce = format!("{}::{}", command, nonce);
            let command_nonce_ciphered = aes256_encrypt_to_base64(&session_key, &command_nonce);

            // Combine the encrypted components
            let c = format!("{}::{}", uid_nonce_ciphered, command_nonce_ciphered);

            // Sign the combined encrypted message with our private key
            let signature = sign_to_base64(private_key, &c);

            // Create payload with encrypted message and signature
            let payload = CipherWithUid {
                uid: uid_nonce_ciphered,
                c: c,
                t: signature
            };

            // Send the encrypted command to the server
            let client = Client::new();
            let url = format!("http://{}/executer_rsa", ip);
            let response = client.post(&url).json(&payload).send().await?;

            // Process the server response
            let res_text = response.text().await?;
            let response: serde_json::Value = serde_json::from_str(&res_text)?;
            if response["status"] != "success" {
                return Err("Server returned error".into());
            }

            // Extract the encrypted output and signature
            let output_nonce_cipher = response["output"].as_str().ok_or("Missing output")?;
            let signature = response["signature"].as_str().ok_or("Missing Signature")?;

            // Verify the signature from the server
            if !verify_signature_from_base64(&bob_pubkey, &output_nonce_cipher, &signature) {
                return Err("Invalid Signature".into());
            }

            // Decrypt the server's response using the session key
            let decrypted_output = aes256_decrypt_from_base64(&session_key, output_nonce_cipher);
            //println!("Decrypted output: {}", decrypted_output);
            
            // Split the output into command result and nonce
            let parts: Vec<&str> = decrypted_output.splitn(2, "::").collect();
            if parts.len() != 2 || parts.iter().any(|part| part.is_empty()) {
                return Err("Invalid format".into());
            }

            // Return only the command output part without the nonce
            let command_output = parts[0];
            return Ok(command_output.to_string());

        }
        "ECC" => {
            // Load the ECC private key for encryption and signing
            let sk = load_private_key_from_pem("../data/myself/ECC_private_key.pem".to_string());

            // Load the recipient's public ECC key for encryption
            let bob_pubkey_path = format!("../data/keys/clients/{}_ecc.pem", uid_bob);
            let bob_pubkey = load_public_key_from_pem(bob_pubkey_path.to_string());

            // Combine user ID, command, and nonce into a single string
            let uid_command_nonce_ciphered = format!("{}::{}::{}", uid, command, nonce);
            
            // Encrypt the combined data with recipient's public key
            let c = encrypt(&bob_pubkey, uid_command_nonce_ciphered.as_bytes());

            // Sign the encrypted data with our private key
            let signature = ecc_sign_to_base64(&sk, c.as_bytes());

            // Create payload with encrypted data and signature
            let payload = Cipher {
                c: c,
                t: signature
            };

            // Send the encrypted command to the server
            let client = Client::new();
            let url = format!("http://{}/executer_ecc", ip);
            let response = client.post(&url).json(&payload).send().await?;

            // Process the server response
            let res_text = response.text().await?;
            let response: serde_json::Value = serde_json::from_str(&res_text)?;
            if response["status"] != "success" {
                return Err("Server returned error".into());
            }

            // Extract the encrypted output and signature
            let output_nonce_cipher = response["output"].as_str().ok_or("Missing output")?;
            let signature = response["signature"].as_str().ok_or("Missing Signature")?;

            // Verify the signature from the server
            if !verify_signature(&bob_pubkey, output_nonce_cipher.as_bytes(), &signature) {
                return Err("Invalid Signature".into());
            }

            // Decrypt the server's response using our private key
            let decrypted_bytes = decrypt(&sk, output_nonce_cipher)?; 
            
            // Convert decrypted bytes to a UTF-8 string
            let decrypted_output = String::from_utf8(decrypted_bytes)
                .map_err(|_| "Output is not valid UTF-8")?;

            // Split the output into command result and nonce
            let parts: Vec<&str> = decrypted_output.splitn(2, "::").collect();

            // Validate the format of the response
            if parts.len() != 2 || parts.iter().any(|part| part.is_empty()) {
                return Err("Invalid format".into());
            }

            // Return only the command output part without the nonce
            let command_output = parts[0];
            return Ok(command_output.to_string());
        }

        "RSA_AES" | "ECC_AES" => {
            // This case handles hybrid encryption using either RSA or ECC for key exchange
            // and AES for data encryption, providing better performance for larger messages

            // Encrypt the user ID and nonce using the appropriate asymmetric algorithm
            let uid_nonce_ciphered = if typ == "RSA_AES" {
                // For RSA, use the recipient's RSA public key
                let bob_pubkey_path = format!("../data/keys/clients/{}_rsa.pem", uid_bob);
                let bob_pubkey = read_public_key_from_file(&bob_pubkey_path);
                let uid_nonce = format!("{}::{}", uid, nonce);
                encrypt_to_base64(&bob_pubkey, &uid_nonce)
            } else {
                // For ECC, use the recipient's ECC public key
                let bob_pubkey_path = format!("../data/keys/clients/{}_ecc.pem", uid_bob);
                let bob_pubkey = load_public_key_from_pem(bob_pubkey_path.to_string());
                let uid_nonce = format!("{}::{}", uid, nonce);
                encrypt(&bob_pubkey, uid_nonce.as_bytes())
            };


            let session_key_raw = std::fs::read_to_string(format!("session_keys/{}_session_key_aes.txt", uid_bob))
                .expect("Não foi possível ler a chave de sessão");

            // Carregar chave AES + IV da sessão
            let aes_key_struct = load_from_base64_string(&session_key_raw);

            // Derivar AES e HMAC a partir da chave de sessão
            let (aes_key, hmac_key) = derive_keys_from_session_key_and_iv(&aes_key_struct.key, &aes_key_struct.iv);

            // Encriptar comando + nonce
            let command_nonce = format!("{}::{}", command, nonce);
            let command_nonce_ciphered = aes256_encrypt_to_base64(&aes_key, &command_nonce);

            // Concatenar tudo em `c`
            let c = format!("{}::{}", uid_nonce_ciphered, command_nonce_ciphered);

            // Assinar `c` com HMAC
            let signature = {
                let sig = hmac_sign(&hmac_key, c.as_bytes());
                base64::engine::general_purpose::STANDARD.encode(sig)
            };

            // Construir payload
            let payload = CipherWithUid {
                uid: uid_nonce_ciphered,
                c: c.clone(),
                t: signature,
            };

            // Enviar para o servidor
            let client = Client::new();
            let url = format!("http://{}:3001/executer_{}", ip, typ.to_lowercase());
            let response = client.post(&url).json(&payload).send().await?;

            let res_text = response.text().await?;
            let response: serde_json::Value = serde_json::from_str(&res_text)?;
            if response["status"] != "success" {
                return Err("Server returned error".into());
            }

            // Validar assinatura e decifrar
            let output_nonce_cipher = response["output"].as_str().ok_or("Missing output")?;
            let signature = response["signature"].as_str().ok_or("Missing Signature")?;

            let decrypted_output = verify_and_decrypt(&aes_key, output_nonce_cipher, signature, &hmac_key)
                .ok_or("Assinatura inválida ou mensagem corrompida")?;

            // Separar resposta
            let parts: Vec<&str> = decrypted_output.splitn(2, "::").collect();
            if parts.len() != 2 || parts.iter().any(|part| part.is_empty()) {
                return Err("Invalid format".into());
            }

            let command_output = parts[0];
            return Ok(command_output.to_string());


        }
        _ => {
            eprintln!("❌ Invalid type");
            return Err("Invalid type".into());
        }

    }

    //Ok(("Command executed successfully").to_string())
}