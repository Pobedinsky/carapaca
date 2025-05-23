use reqwest::Client;
use serde::{Deserialize, Serialize};
use ciphering::rsa::{encrypt_to_base64, sign_to_base64, decrypt_from_base64, verify_signature_from_base64, read_public_key_from_file, RSAKeyPair};
use std::fs::{File};
use std::io::Write;
use ciphering::ecc_el_gammal::{sign_to_base64 as ecc_sign_to_base64, decrypt, encrypt, load_public_key_from_pem, load_private_key_from_pem, verify_signature};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use ciphering::aes::{load_from_base64_string, aes256_encrypt_to_base64, aes256_decrypt_from_base64, verify_and_decrypt, derive_keys_from_session_key_and_iv, hmac_sign};
use base64::Engine;

#[derive(Serialize, Deserialize)]
struct SignatureRequest {
    uid: String,
    signature: String, // base64
}

#[derive(Serialize, Deserialize)]
struct Cipher {
    c: String, // Encrypted session key (base64)
    t: String, // Signature (base64)
}

#[derive(Serialize, Deserialize)]
struct CipherWithUid {
    uid: String,
    c: String, // Encrypted session key (base64)
    t: String, // Signature (base64)
}

#[derive(Deserialize)]
struct ResponseData {
    message: Cipher,
    status: String,
}

pub async fn get_nonce(uid: &str, ip: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = format!("http://{}/get-nonce?uid={}", ip, uid);
    let response = client.get(&url).send().await?;
    let text = response.text().await?;

    println!("Resposta do GET /get-nonce: {}", text);

    let parsed: serde_json::Value = serde_json::from_str(&text)?;
    if parsed["status"] != "success" {
        return Err("Erro ao obter nonce".into());
    }

    let message = parsed["message"].as_str().unwrap_or("");
    let nonce = message.strip_prefix("Nonce: ").unwrap_or("").trim();

    if nonce.is_empty() {
        return Err("Nonce vazio".into());
    }

    Ok(nonce.to_string())
}

pub async fn send_signature_rsa(uid: &str, nonce: &str, ip: &str, uid_bob: &str) -> Result<(), Box<dyn std::error::Error>> {
    let keys = RSAKeyPair::load_from_files(
        "../data/myself/RSA_private_key.pem",
        "../data/myself/RSA_public_key.pem",
    );
    let private_key = &keys.private_key;

    let message = format!("{}{}", uid, nonce);
    let signature = sign_to_base64(private_key, &message);

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
    }

    // Obter a representação SEC1 da chave pública local
    let encoded_point = pk.to_encoded_point(false); // uncompressed
    let local_pk_str = encoded_point.to_string();

    if parts[0] == local_pk_str {
        println!("🔐 A chave pública foi confirmada com sucesso pelo servidor.");
    } else {
        println!("❌ A chave pública retornada não corresponde à local!");
        return Err("Chave pública não confirmada".into());
    }

    Ok(())
}


pub async fn executer(uid: &str, nonce: &str, ip: &str, typ: &str, command: &str, uid_bob: &str) -> Result<String, Box<dyn std::error::Error>> {
    match typ {
        "RSA" => {
            let keys = RSAKeyPair::load_from_files(
                "../data/myself/RSA_private_key.pem",
                "../data/myself/RSA_public_key.pem",
            );

            let private_key = &keys.private_key;

            let session_key = std::fs::read_to_string(format!("session_keys/{}_session_key.txt", uid_bob))
                .expect("Não foi possível ler a chave de sessão");

            let bob_pubkey_path = format!("../data/keys/clients/{}_rsa.pem", uid_bob);
            let bob_pubkey = read_public_key_from_file(&bob_pubkey_path);

            let uid_nonce = format!("{}::{}", uid, nonce);

            let uid_nonce_ciphered = encrypt_to_base64(&bob_pubkey, &uid_nonce);

            let session_key = load_from_base64_string(&session_key);

            let command_nonce = format!("{}::{}", command, nonce);

            let command_nonce_ciphered = aes256_encrypt_to_base64(&session_key, &command_nonce);

            let c = format!("{}::{}", uid_nonce_ciphered, command_nonce_ciphered);

            // Assinar uid cifrado (chave do servidor) + c
            let signature = sign_to_base64(private_key, &c);

            let payload = CipherWithUid {
                uid: uid_nonce_ciphered,
                c: c,
                t: signature
            };

            let client = Client::new();
            let url = format!("http://{}/executer_rsa", ip);
            let response = client.post(&url).json(&payload).send().await?;

            let res_text = response.text().await?;
            let response: serde_json::Value = serde_json::from_str(&res_text)?;
            if response["status"] != "success" {
                return Err("Server returned error".into());
            }

            let output_nonce_cipher = response["output"].as_str().ok_or("Missing output")?;
            let signature = response["signature"].as_str().ok_or("Missing Signature")?;

            if !verify_signature_from_base64(&bob_pubkey, &output_nonce_cipher, &signature) {
                return Err("Invalid Signature".into());
            }

            let decrypted_output = aes256_decrypt_from_base64(&session_key, output_nonce_cipher);
            //println!("Decrypted output: {}", decrypted_output);
            
            let parts: Vec<&str> = decrypted_output.splitn(2, "::").collect();
            if parts.len() != 2 || parts.iter().any(|part| part.is_empty()) {
                return Err("Invalid format".into());
            }

            let command_output = parts[0];
            return Ok(command_output.to_string());

        }
        "ECC" => {
            let sk = load_private_key_from_pem("../data/myself/ECC_private_key.pem".to_string());

            let bob_pubkey_path = format!("../data/keys/clients/{}_ecc.pem", uid_bob);
            let bob_pubkey = load_public_key_from_pem(bob_pubkey_path.to_string());

            let uid_command_nonce_ciphered = format!("{}::{}::{}", uid, command, nonce);
            
            let c = encrypt(&bob_pubkey, uid_command_nonce_ciphered.as_bytes());

            // Assinar uid cifrado (chave do servidor) + c
            let signature = ecc_sign_to_base64(&sk, c.as_bytes());

            let payload = Cipher {
                c: c,
                t: signature
            };

            let client = Client::new();
            let url = format!("http://{}/executer_ecc", ip);
            let response = client.post(&url).json(&payload).send().await?;

            let res_text = response.text().await?;
            let response: serde_json::Value = serde_json::from_str(&res_text)?;
            if response["status"] != "success" {
                return Err("Servidor retornou erro".into());
            }

            let output_nonce_cipher = response["output"].as_str().ok_or("Missing output")?;
            let signature = response["signature"].as_str().ok_or("Missing Signature")?;

            if !verify_signature(&bob_pubkey, output_nonce_cipher.as_bytes(), &signature) {
                return Err("Invalid Signature".into());
            }

            let decrypted_bytes = decrypt(&sk, output_nonce_cipher)?; // Result<Vec<u8>, _>
            let decrypted_output = String::from_utf8(decrypted_bytes)
                .map_err(|_| "Output is not valid UTF-8")?;

            let parts: Vec<&str> = decrypted_output.splitn(2, "::").collect();

            if parts.len() != 2 || parts.iter().any(|part| part.is_empty()) {
                return Err("Invalid format".into());
            }

            let command_output = parts[0];
            return Ok(command_output.to_string());
        }

        "RSA_AES" | "ECC_AES" => {



            let uid_nonce_ciphered = if typ == "RSA_AES" {
                let bob_pubkey_path = format!("../data/keys/clients/{}_rsa.pem", uid_bob);
                let bob_pubkey = read_public_key_from_file(&bob_pubkey_path);
                let uid_nonce = format!("{}::{}", uid, nonce);
                encrypt_to_base64(&bob_pubkey, &uid_nonce)
            } else {
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