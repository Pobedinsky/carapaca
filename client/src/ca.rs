use std::fs;
use std::path::Path;
use aes_gcm::{Aes256Gcm, Nonce}; // AES-GCM types

use serde::{Deserialize, Serialize};
use serde_json::to_string;

use ciphering::rsa::sign_to_base64;
use ciphering::rsa::{verify_signature_from_base64};

use generic_array::GenericArray;
use reqwest::Client;

use rand::Rng;
use base64::{engine::general_purpose, Engine as _};
use openssl::pkey::PKey;
use ciphering::rsa::encrypt_to_base64;

#[derive(Serialize, Deserialize, Debug, Clone)]

pub struct User {
    pub uid: String,
    pub pk_rsa: String,
    pub pk_ecc: String,
    pub ip: String,
}
#[derive(Deserialize, Debug)]
struct ServerResponse {
    nonce: String,
    signature: String,
    user: User,
}

fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);

    let nonce: &GenericArray<u8, <Aes256Gcm as aead::AeadCore>::NonceSize> = Nonce::from_slice(&nonce_bytes);
    general_purpose::STANDARD.encode(nonce)
}



#[derive(Serialize, Deserialize, Debug)]
struct SecureMessage {
    c: String,      // Encrypted message (base64)
    t: String,      // Signature (base64)
    nonce: String,  // Nonce (plaintext, used in response binding)
}

#[derive(Serialize, Deserialize, Debug)]
struct Payload {
    uid: String,
    ip: String,
}

#[derive(Deserialize, Debug)]
struct SecureResponseData {
    message: String,
    nonce: String,
    t: String,
}


pub async fn update_ip_to_server(uid: &str, new_ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let priv_key_pem = fs::read("../data/myself/RSA_private_key.pem")?;
    let priv_key = PKey::private_key_from_pem(&priv_key_pem)?;

    let server_pub_pem = fs::read("../data/myself/CA_rsa_pub.pem")?;
    let server_pub_key = PKey::public_key_from_pem(&server_pub_pem)?;

    let payload = Payload {
        uid: uid.to_string(),
        ip: new_ip.to_string(),
    };

    let json_payload = serde_json::to_string(&payload)?;
    let nonce = generate_nonce();

    let message = format!("{}::{}", json_payload, nonce);

    let encrypted = encrypt_to_base64(&server_pub_key, &message);

    let signature = sign_to_base64(&priv_key, &message);

    let secure_msg = SecureMessage {
        c: encrypted,
        t: signature,
        nonce: nonce.clone(),
    };

    let client = Client::new();
    let res = client
        .post("http://217.129.170.191:3000/wassap-im-ready")
        .json(&secure_msg)
        .send()
        .await?;

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















pub async fn verify_and_store_keys_from_server(uid: &str) -> Result<(), Box<dyn std::error::Error>> {
    let rsa_path = format!("../data/keys/clients/{}_rsa.pem", uid);
    let ecc_path = format!("../data/keys/clients/{}_ecc.pem", uid);
    let ip_path = format!("../data/keys/clients/{}_ip.txt", uid);

    // If already exists, skip
    if Path::new(&rsa_path).exists() && Path::new(&ecc_path).exists() && Path::new(&ip_path).exists(){
        println!("✅ Keys already exist for UID '{}'", uid);
        return Ok(());
    }

    let nonce = generate_nonce();

    // Call server
    let url = format!("http://217.129.170.191:3000/holy-bible/{}?nonce={}", uid, nonce);
    let response = reqwest::get(&url).await?;
    if !response.status().is_success() {
        eprintln!("❌ Server returned error: {}", response.status());
        return Ok(());
    }

    let data: ServerResponse = response.json().await?;
    let user_json = to_string(&data.user)?;
    let signed_msg = format!("{}{}", user_json, data.nonce);

    // Load server public key using your RSA lib's PKey<Public> wrapper
    let server_pub_pem = fs::read("../data/myself/CA_rsa_pub.pem")?;
    let server_pub_key = openssl::pkey::PKey::public_key_from_pem(&server_pub_pem)?;

    

    // Use your own verification function
    let is_valid = verify_signature_from_base64(&server_pub_key, &signed_msg, &data.signature);

    if is_valid {
        println!("✅ Signature is valid. Saving keys.");
        fs::create_dir_all("../data/keys")?;
        fs::create_dir_all("../data/keys/clients")?;
        fs::write(&rsa_path, &data.user.pk_rsa)?;
        fs::write(&ecc_path, &data.user.pk_ecc)?;
        println!("✅ Keys saved to {} and {}", rsa_path, ecc_path);
        println!("✅ IP saved to {}", ip_path);
        fs::write(&ip_path, &data.user.ip)?;
        println!("✅ IP saved to {}", ip_path);
    } else {
        eprintln!("❌ Signature is invalid. Rejecting keys.");
    }

    Ok(())
}
