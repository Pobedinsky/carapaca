mod ca;
mod ip;
mod init;
mod server;

use aes_gcm::{Aes256Gcm, Nonce};
use std::io::{self, Write};
use std::path::Path;
use std::fs;
use generic_array::GenericArray;
use rand::Rng;
use base64::{engine::general_purpose, Engine as _};
use crate::ca::update_ip_to_server;

fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);

    let nonce: &GenericArray<u8, <Aes256Gcm as aead::AeadCore>::NonceSize> = Nonce::from_slice(&nonce_bytes);
    general_purpose::STANDARD.encode(nonce)
}

pub async fn interactive_loop(
    uid: &str,
    nonce: &str,
    ip_bob: &str,
    typ: &str,
    uid_bob: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut prompt = String::new();

    loop {
        if prompt.is_empty() {
            print!("{}@{}:~$ ", uid, ip_bob);
        } else {
            print!("{} ", prompt);
        }

        io::stdout().flush()?; // para garantir que o prompt apareça

        let mut command = String::new();
        io::stdin().read_line(&mut command)?;
        let command = command.trim();

        if command.eq_ignore_ascii_case("exit") {
            match server::executer(uid, nonce, ip_bob, typ, "exit", uid_bob).await {
                Ok(msg) => println!("{}", msg),
                Err(e) => eprintln!("Erro ao enviar comando de saída: {}", e),
            };
            break Ok(());
        }

        match server::executer(uid, nonce, ip_bob, typ, command, uid_bob).await {
            Ok(msg) => {
                if let Some(idx) = msg.rfind('\n') {
                    let (before, after) = msg.split_at(idx + 1);
                    print!("{}", before);
                    prompt = after.trim().to_string();
                    // println!("Prompt atualizado: {}", prompt);
                } else {
                    prompt = msg;
                }
            },
            Err(e) => eprintln!("Erro ao enviar comando: {}", e),
        };
    }
}


#[tokio::main]
async fn main() {

    let ip = match ip::get_public_ip().await {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("❌ Error fetching IP: {}", e);
            return;
        }
    };
    println!("Public IP: {}", ip);
    



    if !Path::new("../.installed_marker").exists() {
        // 🟢 Prompt the UID
        print!("Enter your UID (username or identifier): ");
        io::stdout().flush().unwrap(); // Make sure prompt is shown before input

        let mut uid = String::new();
        io::stdin().read_line(&mut uid).unwrap();
        let uid = uid.trim(); // Remove trailing newline

        // 🟡 Confirm registration
        print!("Proceed to register this UID '{}' with the server? (y/n): ", uid);
        io::stdout().flush().unwrap();

        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm).unwrap();

        if confirm.trim().eq_ignore_ascii_case("y") {
            // 🔵 Get the public IP
            let ip = match ip::get_public_ip().await {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("❌ Failed to get public IP: {}", e);
                    return;
                }
            };

            // 🔵 Call registration function
            match init::register_on_first_install(uid, &ip).await {
                Ok(_) => println!("✅ Registration completed."),
                Err(e) => {eprintln!("❌ Error during registration: {}", e);
                    return;
                },
            }
        } else {
            println!("ℹ️ Registration cancelled.");
        }
    }
    else{
        let uid = fs::read_to_string("../.installed_marker").unwrap();
        update_ip_to_server(&uid, &ip).await.unwrap_or_else(|e| eprintln!("❌ Error updating IP: {}", e));
    }


    print!("Enter recipient UID (username or identifier): ");
    io::stdout().flush().unwrap(); // Make sure prompt is shown before input

    let mut uid_bob = String::new();
    io::stdin().read_line(&mut uid_bob).unwrap();
    let uid_bob = uid_bob.trim(); // Remove trailing newline

    let uid = fs::read_to_string("../.installed_marker").unwrap();


    match ca::verify_and_store_keys_from_server(uid_bob).await {
        Ok(_) => println!("✅ Key verification and storage completed."),
        Err(e) => { eprintln!("❌ Error: {}", e);
            return;
        },
    }

    let ip_bob = fs::read_to_string(format!("../data/keys/clients/{}_ip.txt", uid_bob)).unwrap();
    
    //let typ = "RSA"; // TODO: Make this configurable

    
    print!("Enter encryption type (RSA or ECC): ");
    io::stdout().flush().unwrap(); 

    let mut typ = String::new();
    io::stdin().read_line(&mut typ).unwrap();
    let mut typ = typ.trim().to_string();

    if typ != "RSA" && typ != "ECC" {
        eprintln!("❌ Invalid type. Please enter 'RSA' or 'ECC'.");
        return;
    }

    print!("Do you own a symetric key? (y/n): ");
    io::stdout().flush().unwrap();

    let mut sym_choice = String::new();
    io::stdin().read_line(&mut sym_choice).unwrap();

    if sym_choice.trim().eq_ignore_ascii_case("y") {
        typ = format!("{}_AES", typ);
    }

    if typ != "RSA_AES" && typ != "ECC_AES" {
        let nonce = server::get_nonce(&uid, &ip_bob).await;
        println!("Nonce: {:?}", nonce);
        
        match nonce {
            Ok(nonce) => {
                match &typ {
                    t if t == "RSA" => {
                        if let Err(e) = server::send_signature_rsa(&uid, &nonce, &ip_bob, uid_bob).await {
                            eprintln!("❌ Error sending signature: {}", e);
                            return;
                        }
                    }
                    t if t == "ECC" => {
                        if let Err(e) = server::send_signature_ecc(&uid, &nonce, &ip_bob, uid_bob).await {
                            eprintln!("❌ Error sending signature: {}", e);
                            return;
                        }
                    }
                    _ => {
                        eprintln!("❌ Invalid type");
                        return;
                    }
                }

            }
            Err(e) => {
                eprintln!("❌ Error getting nonce: {}", e);
                return;
            }
        }
    }

    let nonce2 = generate_nonce();
    interactive_loop(&uid, &nonce2, &ip_bob, &typ, uid_bob)
        .await
        .unwrap_or_else(|e| {eprintln!("❌ Error in interactive loop: {}", e); return;});

}
