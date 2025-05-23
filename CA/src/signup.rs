// User Registration and Certificate Management Module
// This file handles user signup requests, certificate verification, and user data retrieval
// It processes encrypted registration data and manages secure communication with users
use ciphering::rsa::{RSAKeyPair, decrypt_from_base64, sign_to_base64, verify_signature_from_base64};
use firestore::errors::FirestoreError;
use crate::db_service::DbService;
use crate::user::User;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use hyper::{Body, Request, Response};
use openssl::pkey::{PKey, Public};
use hyper::body::to_bytes;
use serde_json::Value;

// Structure for encrypted cipher data with digital signature
#[derive(Deserialize, Serialize, Debug)]
struct Cipher {
    c: String,  // Encrypted content
    t: String,  // Digital signature
}

// Structure for user registration message containing all required user information
#[derive(Deserialize, Serialize, Debug)]
struct MessageRegister {
    uid: String,     // User identifier
    pk_rsa: String,  // RSA public key in PEM format
    pk_ecc: String,  // ECC public key in PEM format
    ip: String,      // User's IP address
}

// Structure for response message containing user info and CA public key
#[derive(Deserialize, Serialize, Debug)]
struct MessageReturn {
    uid: String,  // User identifier
    pk: String,   // CA's public key
}

// Store user information in Firestore database
// Arguments:
// * `db` - Database service instance
// * `pk_rsa` - User's RSA public key
// * `pk_ecc` - User's ECC public key
// * `uid` - User identifier
// * `ip` - User's IP address
// Returns: Result with UID on success or FirestoreError on failure
async fn store_in_firestore(db: &DbService, pk_rsa: &str, pk_ecc: &str, uid: &str, ip: &str) -> Result<String, FirestoreError> {
    let user = User {
        uid: uid.to_string(),
        pk_rsa: pk_rsa.to_string(),
        pk_ecc: pk_ecc.to_string(),
        ip: ip.to_string(),
    };



    db.insert(user).await?;
    Ok(uid.to_string())
}

// Create standardized error responses for HTTP requests
// Arguments:
// * `status` - HTTP status code
// * `message` - Error message
// Returns: HTTP Response with error details
fn create_error_response(status: u16, message: String) -> Result<Response<Body>, Infallible> {
    let json_response = serde_json::json!({
        "error": message
    });

    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(json_response.to_string()))
        .unwrap())
}

// Main handler for user signup requests
// Processes incoming HTTP requests for user registration
pub async fn signup_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();

    match serde_json::from_slice::<Cipher>(&body_bytes) {
        Ok(data) => handle_signup_request(data).await,
        Err(e) => create_error_response(400, format!("Invalid JSON: {}", e)),
    }
}

// Convert OpenSSL public key to PEM string format
// Arguments:
// * `public_key` - The public key to convert
// Returns: String representation of the public key in PEM format
fn public_key_to_string(public_key: &PKey<Public>) -> String {
    let rsa = public_key.rsa().unwrap();
    let pem_bytes = rsa.public_key_to_pem_pkcs1().unwrap();
    String::from_utf8(pem_bytes).unwrap()
}


/// Retrieve a user's RSA public key via the get user handler
/// This is a helper function that extracts the RSA public key from user data
/// Arguments:
/// * `uid` - User identifier
/// * `nonce` - Security nonce for the request
/// Returns: Option<String> - The user's RSA public key or None if not found
pub async fn get_user_pk_rsa_via_handler(uid: String, nonce: String) -> Option<String> {
    let response_result = handle_get_user(uid, nonce).await;

    match response_result {
        Ok(response) => {
            let body_bytes = to_bytes(response.into_body()).await.ok()?;
            let json: Value = serde_json::from_slice(&body_bytes).ok()?;

            // Try to access user.pk_rsa from the JSON response
            Some(json.get("user")?.get("pk_rsa")?.as_str()?.to_string())
        }
        Err(_) => None,
    }
}

// Process the actual signup request with encrypted data
// This function handles decryption, signature verification, and user registration
async fn handle_signup_request(data: Cipher) -> Result<Response<Body>, Infallible> {
    // Load CA's RSA key pair for decryption and signing
    let keys = RSAKeyPair::load_from_files(
        "src/keys/RSA_private_key.pem", 
        "src/keys/RSA_public_key.pem"
    );

    let private_key = &keys.private_key;
    //let public_key = &keys.public_key;

    // 1. Split the encrypted content into parts (chunked encryption)
    let encrypted_parts: Vec<&str> = data.c.split("::").collect();
    if encrypted_parts.len() != 4 {
        return create_error_response(400, "Invalid encrypted format".to_string());
    }

    // 2. Decrypt and reconstruct the original JSON
    let mut decrypted_json = String::new();
    for part in encrypted_parts {
        let fragment = match decrypt_from_base64(private_key, part) {
            Ok(text) => text,
            Err(e) => return create_error_response(400, format!("Decryption error: {}", e)),
        };
        decrypted_json.push_str(&fragment);
    }

    // 3. Deserialize the decrypted JSON into MessageRegister structure
    let m: MessageRegister = match serde_json::from_str(&decrypted_json) {
        Ok(data) => data,
        Err(_) => return create_error_response(400, "Invalid JSON format".to_string()),
    };

    // Convert the user's RSA public key from PEM format to OpenSSL PKey
    let public_key = PKey::public_key_from_pem(&(m.pk_rsa.as_bytes())).unwrap();

    // 4. Verify the digital signature of the decrypted message
    if !verify_signature_from_base64(&public_key, &decrypted_json, &data.t) {
        return create_error_response(400, "Invalid signature".to_string());
    }


    // Store the user in the database
    let db = DbService::new().await;
    match store_in_firestore(&db, &m.pk_rsa, &m.pk_ecc, &m.uid, &m.ip).await {
        Ok(_uid) => {
            // Generate response with CA's public key and signature
            let public_key_str = public_key_to_string(&public_key);
            let signature = sign_to_base64(private_key, &public_key_str);

            let response_data = Cipher {
                c: public_key_str,
                t: signature
            };

            let json_response = serde_json::to_string(&response_data).unwrap();
            Ok(Response::new(Body::from(json_response)))
        },
        Err(e) => create_error_response(500, format!("Failed to store user: {}", e)),
    }

}


/// Handler to retrieve all registered users from the database
/// Returns: JSON array of all users or error response
pub async fn handle_get_all() -> Result<Response<Body>, Infallible> {
    let db = DbService::new().await;

    match db.get_all().await {
        Ok(users) => {
            let json = serde_json::to_string(&users).unwrap();
            Ok(Response::new(Body::from(json)))
        }
        Err(e) => create_error_response(500, format!("Firestore error: {}", e)),
    }
}

// Handler to retrieve a specific user by UID with nonce-based security
// Arguments:
// * `uid` - User identifier to look up
// * `nonce` - Security nonce to prevent replay attacks
// Returns: JSON response with user data, nonce, and CA signature
pub async fn handle_get_user(uid: String, nonce: String) -> Result<Response<Body>, Infallible> {
    let db = DbService::new().await;

    match db.get_user(uid.clone()).await {
        Ok(Some(user)) => {
            // Load CA's keys for signing the response
            let keys = RSAKeyPair::load_from_files(
                "src/keys/RSA_private_key.pem",
                "src/keys/RSA_public_key.pem"
            );

            let private_key = &keys.private_key;

            // Serialize user to JSON string
            let user_json_string = serde_json::to_string(&user).unwrap();

            // Concatenate with nonce and sign to prevent tampering
            let message_to_sign = format!("{}{}", user_json_string, nonce);
            let signature = sign_to_base64(private_key, &message_to_sign);

            // Create response with user data, nonce and CA signature
            let response_json = serde_json::json!({
                "user": user,
                "nonce": nonce,
                "signature": signature
            });

            Ok(Response::new(Body::from(response_json.to_string())))
        }
        Ok(None) => create_error_response(404, format!("User with uid {} not found", uid)),
        Err(e) => create_error_response(500, format!("Firestore error: {}", e)),
    }
}
