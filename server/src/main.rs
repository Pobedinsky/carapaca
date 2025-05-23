use aes_gcm::{Aes256Gcm, Nonce}; // AES-GCM types
use aes_gcm::aead::{self}; // Import aead and its traits
use aes_gcm::aead::generic_array::GenericArray;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use k256::elliptic_curve::PublicKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use tokio::runtime::Runtime;
use url::form_urlencoded;
use std::io::Write; // Ensure that the Write trait is in scope
use reqwest::Client; // To make HTTP requests to another server
use ciphering::rsa::{read_public_key_from_file,verify_signature_from_base64, encrypt_to_base64, decrypt_from_base64, sign_to_base64, RSAKeyPair};
use ciphering::aes::{generate_symmetric_key, aes256_encrypt_to_base64, aes256_decrypt_from_base64, load_from_base64_string};
use ciphering::ecc_el_gammal::{verify_signature, load_public_key_from_pem, encrypt, decrypt, load_private_key_from_pem, sign_to_base64 as ecc_sign_to_base64};
use std::path::Path;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::fs::{self, File};
mod shell;

use openssl::pkey::PKey;
use openssl::pkey::Public;
use reqwest::StatusCode;
use base64::{engine::general_purpose, Engine as _};
use ciphering::aes::hmac_verify;
use ciphering::aes::hmac_sign;
use ciphering::aes::derive_keys_from_session_key_and_iv;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub uid: String,
    pub pk_rsa: String,
    pub pk_ecc: String,
    pub ip: String,
}

#[derive(Serialize, Deserialize)]
struct CipherWithUid{
    uid: String,
    c: String, // Encrypted session key (base64)
    t: String, // Signature (base64)
}

#[derive(Serialize, Deserialize)]
struct ResponseData {
    message: String,
    status: String,
}


#[derive(Serialize, Deserialize)]
struct ServerResponse {
    nonce: String,
    signature: String,
    user: UserInfo,
}

#[derive(Serialize, Deserialize)]
struct UserInfo {
    uid: String,
    pk_rsa: String,
    pk_ecc: String,
    ip: String,

}

#[derive(Deserialize, Serialize, Debug)]
struct Cipher {
    c: String,
    t: String,
}


fn read_permitted_users(file_path: &str) -> Vec<String> {
    fs::read_to_string(file_path)
        .unwrap_or_else(|_| String::new())
        .lines()
        .map(|line| line.trim().to_string())
        .collect()
}

fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);

    let nonce: &GenericArray<u8, <Aes256Gcm as aead::AeadCore>::NonceSize> = Nonce::from_slice(&nonce_bytes);
    general_purpose::STANDARD.encode(nonce)
}

async fn handle_get_nonce(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let query = req.uri().query().unwrap_or_default();
    let uid = form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == "uid")
        .map(|(_, value)| value.to_string())
        .unwrap_or_default();

    if uid.is_empty() {
        return json_response("UID is missing", "error", 400);
    }

    let permitted_users = read_permitted_users("../data/permitted_users.txt");
    println!("Permitted users: {:?}", permitted_users);
    println!("UID: {:?}", uid);


    if permitted_users.contains(&uid) {
        // Generate the nonce
        let nonce = generate_nonce();

        // Save the nonce in a file
        let file_path = format!("../data/nonces/{}.txt", uid);
        let mut file = fs::File::create(file_path).expect("Failed to create nonce file");
        writeln!(file, "{}", nonce).expect("Failed to write nonce to file");

        let key_path_rsa = format!("../data/keys/clients/{}_rsa.pem", uid);
        let key_path_ecc = format!("../data/keys/clients/{}_ecc.pem", uid);

        // Check if the public key file exists
        if Path::new(&key_path_rsa).exists() && Path::new(&key_path_ecc).exists() {
            println!("Public key already stored for UID: {}", uid);

            return json_response(&format!("Nonce: {}", nonce), "success", 200);
        }

        else {
            // Generate another nonce if needed
            let nonce2 = generate_nonce();

            // Query the external server
            let client = Client::new();



            let url = format!("http://217.129.170.191:3000/holy-bible/{}?nonce={}", uid, nonce2);
            let res = client.get(url).send().await;

            match res {
                Ok(response) => {
                    // Handle the response from the external server if necessary
                    if response.status().is_success() {
                        let body = response.text().await.unwrap();

                        let server_response: ServerResponse = serde_json::from_str(&body).unwrap();
                        let nonce3 = server_response.nonce.clone();
                        let signature = server_response.signature.clone();
                        let user = server_response.user; 
                        let user_ip = user.ip.clone();
                        let user_pk_rsa = user.pk_rsa.clone();
                        let user_pk_ecc = user.pk_ecc.clone();

                        let user_json_string = serde_json::to_string(&user).unwrap();

                        let message_to_sign = format!("{}{}", user_json_string, nonce3);

                        let public_key = read_public_key_from_file("../data/keys/CA_RSA_public_key.pem");

                        println!("Public Key RSA: {}", user_pk_rsa);
                        println!("Public Key ECC: {}", user_pk_ecc);
                        println!("Message to sign: {}", message_to_sign);
                        println!("Signature: {}", signature);
                        println!("User IP: {}", user_ip);
                        println!("Nonce: {}", nonce3);
                        println!("UID: {}", uid);


                        if !verify_signature_from_base64(&public_key, &message_to_sign, &signature) {
                            return json_response("Invalid signature", "error", 403);
                        }

                        let file_path = format!("../data/keys/clients/{}_rsa.pem", uid);
                        let mut file = fs::File::create(file_path).expect("Failed to create pk_rsa file");
                        write!(file, "{}", user_pk_rsa).expect("Failed to write pk_rsa to file");

                        let file_path = format!("../data/keys/clients/{}_ecc.pem", uid);
                        let mut file = fs::File::create(file_path).expect("Failed to create pk_ecc file");
                        write!(file, "{}", user_pk_ecc).expect("Failed to write pk_ecc to file");

                        return json_response(&format!("Nonce: {}", nonce), "success", 200);
                    } else {
                        return json_response("Error in server response", "error", 500);
                    }
                }
                Err(_) => {
                    return json_response("Failed to query external server", "error", 500);
                }
            }
        };
    } else {
        json_response("UID not permitted", "error", 403)
    }
}



#[derive(Deserialize)]
struct SignatureRequest {
    uid: String,
    signature: String, // Base64 encoded
}

pub fn verify_rsa_ecc(public_key_rsa:&PKey<Public> , public_key_ecc:&PublicKey<k256::Secp256k1>, message: &str, signature: &str) -> i32 {
    if verify_signature_from_base64(public_key_rsa, &message, &signature){
        return 0;
    }
    if verify_signature(public_key_ecc, message.as_bytes(), &signature){
        return 1;
    }
    return -1;
}


async fn handle_digital_signature(req: Request<Body>) -> Result<Response<Body>, Infallible> {

    let whole_body = hyper::body::to_bytes(req.into_body()).await.unwrap();
    
    // Parse JSON into struct
    let sig_req: SignatureRequest = match serde_json::from_slice(&whole_body) {
        Ok(val) => val,
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid request format"))
                .unwrap());
        }
    };

    // Load RSA public key
    let pub_key_path_rsa = format!("../data/keys/clients/{}_rsa.pem", sig_req.uid);
    if !std::path::Path::new(&pub_key_path_rsa).exists() {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("User not permitted or public key_rsa not found"))
            .unwrap());
    }
    let public_key_rsa: PKey<Public> = read_public_key_from_file(&pub_key_path_rsa);

    // Load ECC public key
    let pub_key_path_ecc = format!("../data/keys/clients/{}_ecc.pem", sig_req.uid);
    if !std::path::Path::new(&pub_key_path_ecc).exists() {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("User not permitted or public key_ecc not found"))
            .unwrap());
    }
    let pub_key_path_ecc_clone = pub_key_path_ecc.clone();
    let public_key_ecc = load_public_key_from_pem(pub_key_path_ecc_clone);


    let nonce_path: String = format!("../data/nonces/{}.txt", sig_req.uid);
    let nonce = match fs::read_to_string(&nonce_path) {
        Ok(content) => content.trim().to_string(), // In case file ends with \n
        Err(_) => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Nonce not found"))
                .unwrap());
        }
    };

    let message: String = format!("{}{}", sig_req.uid, nonce);
    let signature = sig_req.signature.clone();

    let typ = verify_rsa_ecc(&public_key_rsa, &public_key_ecc, &message, &signature);

    if typ == 0 {
        let symmetric_key = generate_symmetric_key();

        let session_path = format!("session_keys/{}_session_key.txt", sig_req.uid);

        match File::create(&session_path) {
            Ok(mut file) => {
                if let Err(_) = file.write_all(symmetric_key.as_bytes()) {
                    return json_response("Erro ao guardar chave de sessão", "error", 500);
                }
            },
            Err(_) => {
                return json_response("Erro ao criar ficheiro de sessão", "error", 500);
            }
        }

        
        let keys = RSAKeyPair::load_from_files(
        "../data/myself/RSA_private_key.pem", 
        "../data/myself/RSA_public_key.pem"
        );

        let private_key = &keys.private_key;

        let c = encrypt_to_base64(&public_key_rsa, &symmetric_key);
        let t = sign_to_base64(&private_key, &c);

        let cipher = Cipher { c, t };
        let response = serde_json::json!({
            "message": cipher,
            "status": "success"
        });
        let json = serde_json::to_string(&response).unwrap();

        Ok(Response::builder()
            .status(200)
            .body(Body::from(json))
            .unwrap())

    } else if typ == 1 {
        // Converter para AffinePoint e codificar em SEC1 (uncompressed)
        let encoded_point = (&public_key_ecc).to_encoded_point(false); // false = uncompressed
        let nonce2 = generate_nonce();
        
        let nonce_pk = format!("{}::{}", encoded_point.to_string(), nonce2);
        let sk = load_private_key_from_pem("../data/myself/ECC_private_key.pem".to_string());
            // Agora sim: cifrar os bytes da chave pública com ela mesma
        let c = encrypt(&public_key_ecc, nonce_pk.as_bytes());
        let t = ecc_sign_to_base64(&sk, c.as_bytes());

        let cipher = Cipher { c, t };
        let response = serde_json::json!({
            "message": cipher,
            "status": "success"
        });
        let json = serde_json::to_string(&response).unwrap();

        Ok(Response::builder()
            .status(200)
            .body(Body::from(json))
            .unwrap())

    } 
    else {
        return json_response("Invalid signature", "error", 403);
    }
}

fn split_parts(c: &str, n: usize) -> Result<Vec<&str>, Result<Response<Body>, Infallible>> {
    let parts: Vec<&str> = c.splitn(n, "::").collect();
    if parts.len() != n || parts.iter().any(|part| part.is_empty()) {
        Err(json_response("Invalid format", "error", 400))
    } else {
        Ok(parts)
    }
}

async fn executer_rsa(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let payload: CipherWithUid = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(_) => return json_response("Invalid JSON payload", "error", 400),
    };

    let CipherWithUid { uid: uid_nonce_ciphered, c, t } = payload;

    let keys = RSAKeyPair::load_from_files(
        "../data/myself/RSA_private_key.pem", 
        "../data/myself/RSA_public_key.pem"
        );

    //let pk = &keys.public_key;
    let sk = &keys.private_key;

    let uid_nonce = decrypt_from_base64(&sk, &uid_nonce_ciphered);

    let parts = match split_parts(&uid_nonce, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };


    let uid = parts[0];
    let nonce = parts[1];

    // Carregar chave pública do cliente
    let client_rsa_key_path: String = format!("../data/keys/clients/{}_rsa.pem", uid);
    if !Path::new(&client_rsa_key_path).exists() {
        return json_response("Public key not found", "error", 404);
    }
    let client_pubkey = read_public_key_from_file(&client_rsa_key_path);

    // Verificar assinatura
    if !verify_signature_from_base64(&client_pubkey, &c, &t) {
        return json_response("Invalid signature", "error", 403);
    }

    // Carregar chave privada do servidor para decifrar chave de sessão
    let session_key = std::fs::read_to_string(format!("session_keys/{}_session_key.txt", uid))
        .map_err(|_| println!("⚠️ Chave de sessão não encontrada para {}", uid)).unwrap();

    let session_key = load_from_base64_string(&session_key);

    let parts = match split_parts(&c, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };


    let command_nonce_cipher = parts[1];
    let command_nonce = aes256_decrypt_from_base64(&session_key, command_nonce_cipher);

    let parts = match split_parts(&command_nonce, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };


    let command = parts[0];
    let nonce2 = parts[1];

    if nonce != nonce2 {
        return json_response("Invalid nonce", "error", 403);
    }

    match shell::execute_remote_command(&uid, &command).await {
        Ok(output) => {
            let nonce = generate_nonce();
            let output_nonce = format!("{}::{}", &output, &nonce);

            let output_nonce_cipher = aes256_encrypt_to_base64(&session_key, &output_nonce);

            // Assinar o output_nonce_cipher com a chave privada do servidor
            let signature = sign_to_base64(&sk, &output_nonce_cipher);

            // Construir resposta JSON com o output cifrado e assinatura
            let response = serde_json::json!({
                "output": output_nonce_cipher,
                "signature": signature,
                "status": "success"
            });
            let json = serde_json::to_string(&response).unwrap();

            Ok(Response::builder()
                .status(200)
                .body(Body::from(json))
                .unwrap())
        }
        Err(err) => {
            return json_response(&err, "error", 500);
        }
    }


}


async fn executer_ecc(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let payload: Cipher = match serde_json::from_slice(&body_bytes) {
        Ok(p) => p,
        Err(_) => return json_response("Invalid JSON payload", "error", 400),
    };

    let Cipher { c, t } = payload;

    let sk = load_private_key_from_pem("../data/myself/ECC_private_key.pem".to_string());

    // Decifrar mensagem
    let decrypted_bytes = match decrypt(&sk, &c) {
        Ok(msg) => msg,
        Err(_) => return json_response("Falha ao decifrar ECC", "error", 500),
    };

    let decrypted_str = String::from_utf8_lossy(&decrypted_bytes);

    let parts = match split_parts(&decrypted_str, 3) {
        Ok(p) => p,
        Err(resp) => return resp,
    };


    let uid = parts[0];
    let command = parts[1];

    // Load ECC public key
    let pub_key_path_ecc = format!("../data/keys/clients/{}_ecc.pem", uid);
    if !std::path::Path::new(&pub_key_path_ecc).exists() {
        return Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("User not permitted or public key_ecc not found"))
            .unwrap());
    }

    let public_key_ecc = load_public_key_from_pem(pub_key_path_ecc);

    // Verificar assinatura
    if verify_signature(&public_key_ecc, c.as_bytes(), &t) {
        match shell::execute_remote_command(&uid, &command).await {
            Ok(output) => {
                
                let nonce = generate_nonce();
                let output_nonce = format!("{}::{}", &output, &nonce);

                let output_nonce_cipher = encrypt(&public_key_ecc, output_nonce.as_bytes());

                // Assinar o output_nonce_cipher com a chave privada do servidor
                let signature = ecc_sign_to_base64(&sk, output_nonce_cipher.as_bytes());

                // Construir resposta JSON com o output cifrado e assinatura
                let response = serde_json::json!({
                    "output": output_nonce_cipher,
                    "signature": signature,
                    "status": "success"
                });
                let json = serde_json::to_string(&response).unwrap();

                Ok(Response::builder()
                    .status(200)
                    .body(Body::from(json))
                    .unwrap())

            }
            Err(err) => {
                return json_response(&err, "error", 500);
            }
        }
    }else{
        return json_response("Invalid signature", "error", 403)
    }
}


async fn executer_rsa_aes(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let payload: CipherWithUid = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(_) => return json_response("Invalid JSON payload", "error", 400),
    };

    let keys = RSAKeyPair::load_from_files(
        "../data/myself/RSA_private_key.pem", 
        "../data/myself/RSA_public_key.pem"
        );

    //let pk = &keys.public_key;
    let sk = &keys.private_key;

    let CipherWithUid { uid: uid_nonce_ciphered, c, t } = payload;

    let uid_nonce = decrypt_from_base64(&sk, &uid_nonce_ciphered);

    let parts = match split_parts(&uid_nonce, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let uid = parts[0];
    let nonce = parts[1];

    // Carregar chave de sessão AES + IV
    let session_key_raw = match std::fs::read_to_string(format!("session_keys/{}_session_key_aes.txt", uid)) {
                    Ok(content) => content,
                    Err(_) => return json_response("Session key not found", "error", 500),
                };

    // Deserializar chave de sessão
    let session_key = load_from_base64_string(&session_key_raw);

    // Derivar a chave AES e a chave HMAC a partir da chave de sessão
    let (aes_key, hmac_key) = derive_keys_from_session_key_and_iv(&session_key.key, &session_key.iv);

    // Verificar a assinatura HMAC do campo `c`
    if !hmac_verify(&hmac_key, c.as_bytes(), &(base64::engine::general_purpose::STANDARD.decode(t)).unwrap_or_default()) {
        return json_response("Invalid HMAC signature", "error", 403);
    }

    // Separar o campo `c` em partes: UID criptografado + comando criptografado
    let parts = match split_parts(&c, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let _uid_cipher = parts[0]; // O UID já está contido em `uid_nonce_ciphered`
    let command_nonce_cipher = parts[1];

    // Descriptografar o comando + nonce usando a chave AES
    let decrypted_command_nonce = aes256_decrypt_from_base64(&aes_key, command_nonce_cipher);

    // Separar o comando e o nonce
    let parts = match split_parts(&decrypted_command_nonce, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let command = parts[0];
    let nonce2 = parts[1];

    if nonce != nonce2 {
        return json_response("Invalid nonce", "error", 403);
    }

    // Executar o comando remoto
    match shell::execute_remote_command(&uid, &command).await {
        Ok(output) => {
            let nonce = generate_nonce();
            let output_nonce = format!("{}::{}", &output, &nonce);

            // Encriptar o resultado + nonce usando a chave AES
            let output_nonce_cipher = aes256_encrypt_to_base64(&aes_key, &output_nonce);

            // Assinar o resultado criptografado com HMAC
            let signature = hmac_sign(&hmac_key, output_nonce_cipher.as_bytes());
            let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);

            // Construir resposta JSON
            let response = serde_json::json!({
                "output": output_nonce_cipher,
                "signature": signature_b64,
                "status": "success"
            });

            let json = serde_json::to_string(&response).unwrap();

            Ok(Response::builder()
                .status(200)
                .body(Body::from(json))
                .unwrap())
        }
        Err(err) => {
            return json_response(&err, "error", 500);
        }
    }
}


async fn executer_ecc_aes(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let payload: CipherWithUid = match serde_json::from_slice(&body_bytes) {
        Ok(val) => val,
        Err(_) => return json_response("Invalid JSON payload", "error", 400),
    };

    let sk = load_private_key_from_pem("../data/myself/ECC_private_key.pem".to_string());

    let CipherWithUid { uid: uid_nonce_ciphered, c, t } = payload;

    // Decifrar mensagem
    let decrypted_bytes = match decrypt(&sk, &uid_nonce_ciphered) {
        Ok(msg) => msg,
        Err(_) => return json_response("Falha ao decifrar ECC", "error", 500),
    };

    let uid_nonce = String::from_utf8_lossy(&decrypted_bytes);

    let parts = match split_parts(&uid_nonce, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };

    let uid = parts[0];
    let nonce = parts[1];

    // Carregar chave de sessão AES + IV
    let session_key_raw = match std::fs::read_to_string(format!("session_keys/{}_session_key_aes.txt", uid)) {
                    Ok(content) => content,
                    Err(_) => return json_response("Session key not found", "error", 500),
                };

    // Deserializar chave de sessão
    let session_key = load_from_base64_string(&session_key_raw);

    // Derivar a chave AES e a chave HMAC a partir da chave de sessão
    let (aes_key, hmac_key) = derive_keys_from_session_key_and_iv(&session_key.key, &session_key.iv);

    // Verificar a assinatura HMAC do campo `c`
    if !hmac_verify(&hmac_key, c.as_bytes(), &(base64::engine::general_purpose::STANDARD.decode(t)).unwrap_or_default()) {
        return json_response("Invalid HMAC signature", "error", 403);
    }

    // Separar o campo `c` em partes: UID criptografado + comando criptografado
    let parts = match split_parts(&c, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let _uid_cipher = parts[0]; // O UID já está contido em `uid_nonce_ciphered`
    let command_nonce_cipher = parts[1];

    // Descriptografar o comando + nonce usando a chave AES
    let decrypted_command_nonce = aes256_decrypt_from_base64(&aes_key, command_nonce_cipher);

    // Separar o comando e o nonce
    let parts = match split_parts(&decrypted_command_nonce, 2) {
        Ok(p) => p,
        Err(resp) => return resp,
    };
    let command = parts[0];
    let nonce2 = parts[1];

    if nonce != nonce2 {
        return json_response("Invalid nonce", "error", 403);
    }

    // Executar o comando remoto
    match shell::execute_remote_command(&uid, &command).await {
        Ok(output) => {
            let nonce = generate_nonce();
            let output_nonce = format!("{}::{}", &output, &nonce);

            // Encriptar o resultado + nonce usando a chave AES
            let output_nonce_cipher = aes256_encrypt_to_base64(&aes_key, &output_nonce);

            // Assinar o resultado criptografado com HMAC
            let signature = hmac_sign(&hmac_key, output_nonce_cipher.as_bytes());
            let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature);

            // Construir resposta JSON
            let response = serde_json::json!({
                "output": output_nonce_cipher,
                "signature": signature_b64,
                "status": "success"
            });

            let json = serde_json::to_string(&response).unwrap();

            Ok(Response::builder()
                .status(200)
                .body(Body::from(json))
                .unwrap())
        }
        Err(err) => {
            return json_response(&err, "error", 500);
        }
    }
}


async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match req.uri().path() {
        "/get-nonce" => handle_get_nonce(req).await,
        "/tuc-tuc" => handle_digital_signature(req).await,
        "/executer_rsa" => executer_rsa(req).await,
        "/executer_ecc" => executer_ecc(req).await,
        "/executer_rsa_aes" => executer_rsa_aes(req).await,
        "/executer_ecc_aes" => executer_ecc_aes(req).await,
        _ => json_response("Route not found", "error", 404),
    }
}
 

fn json_response(message: &str, status: &str, status_code: u16) -> Result<Response<Body>, Infallible> {
    let response_data = ResponseData {
        message: message.to_string(),
        status: status.to_string(),
    };

    let json = serde_json::to_string(&response_data).unwrap();

    Ok(Response::builder()
        .status(status_code)
        .body(Body::from(json))
        .unwrap())
}

fn main() {
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        let addr = ([0, 0, 0, 0], 3001).into();

        let make_svc = make_service_fn(|_conn| async {
            Ok::<_, Infallible>(service_fn(handle_request))
        });

        let server = Server::try_bind(&addr)
            .unwrap_or_else(|e| {
                eprintln!("Server bind error: {}", e);
                std::process::exit(1);
            })
            .serve(make_svc);

        println!("Server running on http://{}", addr);

        if let Err(e) = server.await {
            eprintln!("Server error: {}", e);
        }
    });
}