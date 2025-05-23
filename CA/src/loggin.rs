use hyper::{Body, Request, Response};
use serde::{Serialize, Deserialize};
use std::convert::Infallible;
use ciphering::rsa::{decrypt_from_base64, sign_to_base64, verify_signature_from_base64, RSAKeyPair};
use crate::db_service::DbService;

use openssl::pkey::{PKey};


use crate::signup::{get_user_pk_rsa_via_handler};

#[derive(Serialize, Deserialize)]
struct ResponseData {
    message: String,
    status: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct LoginMessage {
    uid: String,
    ip_uid: String,  

}

#[derive(Deserialize, Serialize, Debug)]
struct SecureMessage{
    c: String, // {uid, ip}nonce
    t: String,
    nonce: String
}

#[derive(Deserialize, Debug)]
struct Payload {
    uid: String,
    ip: String,
}

#[derive(Serialize, Deserialize)]
struct SecureResponseData {
    message: String,
    nonce: String,
    t: String
}


pub async fn handle_update_ip(req: Request<Body>) -> Result<Response<Body>, Infallible>{
    let body_req = hyper::body::to_bytes(req.into_body()).await.unwrap();

    let post_data: Result<SecureMessage, _> = serde_json::from_slice(&body_req);

    match post_data{
        Ok(data) => {
            let cipher = data.c;
            let t = data.t;
            let nonce = data.nonce;

            let loaded_keypair = RSAKeyPair::load_from_files("src/keys/RSA_private_key.pem", "src/keys/RSA_public_key.pem");

            let m = decrypt_from_base64(&loaded_keypair.private_key, &cipher).unwrap();

            

            //{ui,ip}::nonce

            let parts: Vec<&str> = m.split("::").collect();
            if parts.len() != 2 {
                eprintln!("Malformed decrypted message: expected format '{{uid,ip}}::nonce'");
                return Ok(Response::builder()
                    .status(400)
                    .body(Body::from("Malformed decrypted message"))
                    .unwrap());
            }


           

            let json_part = parts[0];
            let extracted_nonce = parts[1];

             println!("{}", json_part);

            // Parse JSON into struct
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

            //payload.uid, payload.ip

            let uid_a = payload.uid.clone();


         
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


            let pk_rsa_pem: String = pk_rsa.clone(); // Or however you retrieved it

            let public_key = PKey::public_key_from_pem(pk_rsa_pem.as_bytes()).unwrap();

            

            if !verify_signature_from_base64(&public_key, &m, &t) {
                eprintln!("Signature verification failed");
                return Ok(Response::builder()
                    .status(401)
                    .body(Body::from("Invalid signature"))
                    .unwrap());
            }    
                let db = DbService::new().await;
                let new_ip = payload.ip;


                match db.update_user_ip(uid_a.clone(), new_ip.clone()).await {
                    Ok(_) => {
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
            Ok(Response::builder()
                            .status(500)
                            .body(Body::from("Failed to fetch data"))
                            .unwrap())
                    }

        }
      
}
