use reqwest::Client;
use serde::{Deserialize, Serialize};
use ciphering::rsa::{encrypt_to_base64, sign_to_base64, RSAKeyPair};
use std::{fs, path::Path};
use ciphering::rsa::{read_public_key_from_file};
use ciphering::ecc_el_gammal::{save_keypair_to_pem, generate_keypair};
use serde_json::Value;

fn generate_rsa_keypair_and_save() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = RSAKeyPair::generate(2048);
    keypair.save_to_files("../data/myself/RSA_private_key.pem", "../data/myself/RSA_public_key.pem");
    print!("RSA keypair generated and saved to files.\n");
    Ok(())
}

fn generate_ecc_keypair_and_save() -> Result<(), Box<dyn std::error::Error>> {
    let (sk, pk) = generate_keypair();
    let _ = save_keypair_to_pem(&sk, &pk, "../data/myself/ECC_private_key.pem", "../data/myself/ECC_public_key.pem");
    print!("ECC keypair generated and saved to files.\n");
    Ok(())
}


#[derive(Deserialize, Serialize, Debug)]
struct MessageRegister {
    uid: String,
    pk_rsa: String,
    pk_ecc: String,
    ip: String,
}

#[derive(Serialize, Deserialize)]
struct Cipher {
    c: String, // Encrypted message (concatenated)
    t: String, // Signature
}

/// Split a string into N approximately equal parts
fn split_equally(input: &str, parts: usize) -> Vec<String> {
    let len = input.len();
    let part_size = (len + parts - 1) / parts;
    input
        .as_bytes()
        .chunks(part_size)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect()
}







pub async fn register_on_first_install(uid: &str, ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    let marker_file = "../.installed_marker";

    // ✅ Skip if already registered
    if Path::new(marker_file).exists() {
        println!("Already registered. Skipping registration.");
        return Ok(());
    }

    // Generate RSA and ECC key pairs
    let _ = generate_rsa_keypair_and_save()?;
    let _ = generate_ecc_keypair_and_save()?;

    // Load RSA keys
    let keys = RSAKeyPair::load_from_files(
        "../data/myself/RSA_private_key.pem",
        "../data/myself/RSA_public_key.pem",
    );

    let server_pub_key = read_public_key_from_file("../data/myself/CA_rsa_pub.pem");

    let private_key = &keys.private_key;
    //let public_key = &keys.public_key;

    let pk_rsa = fs::read_to_string("../data/myself/RSA_public_key.pem")?;
    let pk_ecc = fs::read_to_string("../data/myself/ECC_public_key.pem")?;

    println!("Public RSA Key: {}", pk_rsa);
    println!("Public ECC Key: {}", pk_ecc);

    // Create message
    let message = MessageRegister {
        uid: uid.to_string(),
        ip: ip.to_string(),
        pk_rsa: pk_rsa.to_string(),
        pk_ecc: pk_ecc.to_string(),
    };

    let json_message = serde_json::to_string(&message)?;

    // Encrypt in 4 chunks
    let parts = split_equally(&json_message, 4);
    let mut encrypted_parts = Vec::new();
    for part in parts {
        let encrypted = encrypt_to_base64(&server_pub_key, &part);
        encrypted_parts.push(encrypted);
    }

    let encrypted_combined = encrypted_parts.join("::");
    let signature = sign_to_base64(private_key, &json_message);

    let cipher_payload = Cipher {
        c: encrypted_combined,
        t: signature,
    };

    // Send to server
    let client = Client::new();
    let res = client
        .post("http://217.129.170.191:3000/hello-i-was-born")
        .json(&cipher_payload)
        .send()
        .await?;

    let body = res.text().await?;

    if let Ok(json) = serde_json::from_str::<Value>(&body) {
        if let Some(error_msg) = json.get("error").and_then(|v| v.as_str()) {
            if error_msg.contains("AlreadyExists") {
                return Err("❌ Error: UID already exists.".into());
            }else{
                return Err(format!("❌ Error: {}", error_msg).into());
            }
        }
    }

    println!("Server response: {}", body);

    // ✅ Mark as installed
    fs::write(marker_file, uid)?;

    Ok(())
}
