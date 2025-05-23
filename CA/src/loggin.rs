// Login and Authentication Module
// This file handles secure login operations and IP address updates
// It verifies digital signatures and manages secure communication with clients
use hyper::{Body, Request, Response};
use serde::{Serialize, Deserialize};
use std::convert::Infallible;
use ciphering::rsa::{decrypt_from_base64, sign_to_base64, verify_signature_from_base64, RSAKeyPair};
use crate::db_service::DbService;

use openssl::pkey::{PKey};


use crate::signup::{get_user_pk_rsa_via_handler};

// Standard response structure for HTTP responses
#[derive(Serialize, Deserialize)]
struct ResponseData {
    message: String,
    status: String,
}

// Structure for login message containing user identification and IP
#[derive(Deserialize, Serialize, Debug)]
struct LoginMessage {
    uid: String,     // User identifier
    ip_uid: String,  // IP address of the user

}

// Structure for secure encrypted messages with signature
#[derive(Deserialize, Serialize, Debug)]
struct SecureMessage{
    c: String,     // Encrypted message: {uid, ip}nonce
    t: String,     // Digital signature
    nonce: String  // Nonce for replay protection
}

// Structure for parsing the decrypted payload
#[derive(Deserialize, Debug)]
struct Payload {
    uid: String,  // User identifier
    ip: String,   // New IP address
}

// Structure for secure response data with signature
#[derive(Serialize, Deserialize)]
struct SecureResponseData {
    message: String,  // Response message (usually the new IP)
    nonce: String,    // Nonce used in the operation
    t: String         // Digital signature of the response
}


// Handler for updating user IP addresses securely
// This function processes encrypted and signed requests to update user IP addresses
pub async fn handle_update_ip(req: Request<Body>) -> Result<Response<Body>, Infallible>{
    // Extract the request body
    let body_req = hyper::body::to_bytes(req.into_body()).await.unwrap();

    // Parse the incoming JSON data
    let post_data: Result<SecureMessage, _> = serde_json::from_slice(&body_req);

    match post_data{
        Ok(data) => {
            let cipher = data.c;     // Encrypted message
            let t = data.t;          // Digital signature
            let nonce = data.nonce;  // Nonce for replay protection

            // Load the CA's RSA key pair for decryption
            let loaded_keypair = RSAKeyPair::load_from_files("src/keys/RSA_private_key.pem", "src/keys/RSA_public_key.pem");

            // Decrypt the message using the CA's private key
            let m = decrypt_from_base64(&loaded_keypair.private_key, &cipher).unwrap();

            

            // Parse the decrypted message: expected format is "{uid,ip}::nonce"
            let parts: Vec<&str> = m.split("::").collect();
            if parts.len() != 2 {
                eprintln!("Malformed decrypted message: expected format '{{uid,ip}}::nonce'");
                return Ok(Response::builder()
                    .status(400)
                    .body(Body::from("Malformed decrypted message"))
                    .unwrap());
            }

           

            let json_part = parts[0];           // JSON payload with uid and ip
            let extracted_nonce = parts[1];     // Extracted nonce

             println!("{}", json_part);

            // Parse the JSON payload into a Payload struct
            let payload: Payload = match serde_json::from_str(json_part) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Failed to parse payload JSON: {}", e);
                    return Ok(Response::builder()
                        .status(400)
                        .body(Body::from("Invalid payload JSON"))
                        .unwrap());
                }
            };

            // Extract user ID for verification
            let uid_a = payload.uid.clone();

         
            // Retrieve the user's RSA public key for signature verification
            let pk_rsa = match get_user_pk_rsa_via_handler(uid_a.clone(), extracted_nonce.to_string()).await {
                Some(pk) => pk,
                None => {
                    eprintln!("Failed to retrieve pk_rsa");
                    return Ok(Response::builder()
                    .status(400)
                    .body(Body::from("Malformed decrypted message"))
                    .unwrap());
                }
            };


            let pk_rsa_pem: String = pk_rsa.clone(); // Retrieved public key in PEM format

            // Convert PEM to OpenSSL PKey for signature verification
            let public_key = PKey::public_key_from_pem(pk_rsa_pem.as_bytes()).unwrap();

            

            // Verify the digital signature of the message
            if !verify_signature_from_base64(&public_key, &m, &t) {
                eprintln!("Signature verification failed");
                return Ok(Response::builder()
                    .status(401)
                    .body(Body::from("Invalid signature"))
                    .unwrap());
            }    
                // Create database service instance
                let db = DbService::new().await;
                let new_ip = payload.ip;

                // Update the user's IP address in the database
                match db.update_user_ip(uid_a.clone(), new_ip.clone()).await {
                    Ok(_) => {
                        // Sign the response with CA's private key
                        let t_s = sign_to_base64(&loaded_keypair.private_key, &(format!("{}::{}", new_ip, nonce)));
                        let response_data = SecureResponseData {
                            message: new_ip.to_string(),
                            nonce: nonce.to_string(),
                            t: t_s.clone()
                        };

                        let json_response = serde_json::to_string(&response_data).unwrap();

                        Ok(Response::new(Body::from(json_response)))
                    }
                    
                    Err(_) => {
                        Ok(Response::builder()
                            .status(500)
                            .body(Body::from("Failed to update IP"))
                            .unwrap())
                    }
                }

            
         
        }

        Err(_) =>{
            // Handle JSON parsing errors
            Ok(Response::builder()
                            .status(500)
                            .body(Body::from("Failed to fetch data"))
                            .unwrap())
                    }

        }
      
}
