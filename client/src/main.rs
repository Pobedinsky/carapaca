/**
 * Client Module for the Carapaca Secure Shell System
 * 
 * This is the main entry point for the client application which manages secure
 * communication with the server using cryptographic protocols including RSA,
 * ECC, and AES encryption.
 */

// Import local modules
mod ca;       // Certificate Authority related functions
mod ip;       // IP address management functions
mod init;     // Initialization and setup procedures
mod server;   // Server communication functions

// External library imports
use aes_gcm::{Aes256Gcm, Nonce};         // AES-GCM encryption components
use std::io::{self, Write};              // Standard I/O operations
use std::path::Path;                     // Filesystem path handling
use std::fs;                             // Filesystem operations
use generic_array::GenericArray;         // Generic array implementation for cryptographic uses
use rand::Rng;                           // Random number generation
use base64::{engine::general_purpose, Engine as _}; // Base64 encoding/decoding
use crate::ca::update_ip_to_server;      // Import IP update function from Certificate Authority module

/**
 * Generates a cryptographically secure nonce (number used once)
 *
 * Creates a random 12-byte nonce suitable for use with AES-GCM encryption
 * and returns it as a base64-encoded string.
 *
 * @return String - The base64-encoded nonce
 */
fn generate_nonce() -> String {
    // Create a cryptographically secure random number generator
    let mut rng = rand::thread_rng();
    
    // Create a buffer for the nonce bytes
    let mut nonce_bytes = [0u8; 12];
    
    // Fill the buffer with random bytes
    rng.fill(&mut nonce_bytes);

    // Convert to the proper GenericArray format required by AES-GCM
    let nonce: &GenericArray<u8, <Aes256Gcm as aead::AeadCore>::NonceSize> = Nonce::from_slice(&nonce_bytes);
    
    // Encode the nonce bytes as a base64 string and return
    general_purpose::STANDARD.encode(nonce)
}

/**
 * Manages an interactive shell session with the remote server
 *
 * This function creates a shell-like interface for the user to interact with
 * the remote server. It handles command input, communication with the server,
 * and display of command results.
 *
 * @param uid - User identifier of the client
 * @param nonce - Cryptographic nonce for secure communication
 * @param ip_bob - IP address of the server to connect to
 * @param typ - Type of encryption to use (RSA, ECC, or AES)
 * @param uid_bob - User identifier of the server
 * @return Result<(), Box<dyn std::error::Error>> - Success or error result
 */
pub async fn interactive_loop(
    uid: &str,
    nonce: &str,
    ip_bob: &str,
    typ: &str,
    uid_bob: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Store the current prompt text
    let mut prompt = String::new();

    // Main command loop
    loop {
        // Display appropriate prompt based on context
        if prompt.is_empty() {
            // Standard shell-like prompt
            print!("{}@{}:~$ ", uid, ip_bob);
        } else {
            // Custom prompt from server response
            print!("{} ", prompt);
        }

        // Ensure prompt is displayed immediately
        io::stdout().flush()?;

        // Read user command input
        let mut command = String::new();
        io::stdin().read_line(&mut command)?;
        let command = command.trim();

        // Check if user wants to exit the shell
        if command.eq_ignore_ascii_case("exit") {
            match server::executer(uid, nonce, ip_bob, typ, "exit", uid_bob).await {
                Ok(msg) => println!("{}", msg),
                Err(e) => eprintln!("Error sending exit command: {}", e),
            };
            break Ok(());
        }

        // Execute the command on the server
        match server::executer(uid, nonce, ip_bob, typ, command, uid_bob).await {
            Ok(msg) => {
                // Handle server response, which may contain a new prompt
                if let Some(idx) = msg.rfind('\n') {
                    // Split response into output and new prompt
                    let (before, after) = msg.split_at(idx + 1);
                    print!("{}", before);
                    prompt = after.trim().to_string();
                    // println!("Updated prompt: {}", prompt);
                } else {
                    // No newline, entire response is the new prompt
                    prompt = msg;
                }
            },
            Err(e) => eprintln!("Error sending command: {}", e),
        };
    }
}


/**
 * Main entry point for the Carapaca client application
 * 
 * This function initializes the client, handles first-time setup if needed,
 * and manages the connection to the server through the interactive shell.
 */
#[tokio::main]
async fn main() {
    // Get the public IP address of this client
    let ip = match ip::get_public_ip().await {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("❌ Error fetching IP: {}", e);
            return;
        }
    };
    println!("Public IP: {}", ip);
    
    // First-time setup process
    if !Path::new("../.installed_marker").exists() {
        // Prompt for user identifier
        print!("Enter your UID (username or identifier): ");
        io::stdout().flush().unwrap(); // Ensure prompt is displayed before waiting for input

        // Read and parse user input
        let mut uid = String::new();
        io::stdin().read_line(&mut uid).unwrap();
        let uid = uid.trim(); // Remove trailing whitespace and newline

        // Confirm registration with the server
        print!("Proceed to register this UID '{}' with the server? (y/n): ", uid);
        io::stdout().flush().unwrap();

        // Read user confirmation input
        let mut confirm = String::new();
        io::stdin().read_line(&mut confirm).unwrap();

        if confirm.trim().eq_ignore_ascii_case("y") {
            // Get the public IP address again to ensure it's current
            let ip = match ip::get_public_ip().await {
                Ok(ip) => ip,
                Err(e) => {
                    eprintln!("❌ Failed to get public IP: {}", e);
                    return;
                }
            };

            // Register the user with the server/CA for the first time
            match init::register_on_first_install(uid, &ip).await {
                Ok(_) => println!("✅ Registration completed."),
                Err(e) => {
                    eprintln!("❌ Error during registration: {}", e);
                    return;
                },
            }
        } else {
            println!("ℹ️ Registration cancelled.");
        }
    }
    else {
        // If already installed, just update IP address on the server
        let uid = fs::read_to_string("../.installed_marker").unwrap();
        update_ip_to_server(&uid, &ip).await.unwrap_or_else(|e| eprintln!("❌ Error updating IP: {}", e));
    }


    // Prompt for the recipient's user identifier
    print!("Enter recipient UID (username or identifier): ");
    io.stdout().flush().unwrap(); // Ensure prompt is displayed before waiting for input

    // Read and parse recipient's identifier
    let mut uid_bob = String::new();
    io::stdin().read_line(&mut uid_bob).unwrap();
    let uid_bob = uid_bob.trim(); // Remove trailing whitespace and newline

    // Get current user's identifier from the marker file
    let uid = fs::read_to_string("../.installed_marker").unwrap();

    // Verify recipient's keys with the Certificate Authority and store them locally
    match ca::verify_and_store_keys_from_server(uid_bob).await {
        Ok(_) => println!("✅ Key verification and storage completed."),
        Err(e) => { 
            eprintln!("❌ Error: {}", e);
            return;
        },
    }

    // Get recipient's IP address from the stored file
    let ip_bob = fs::read_to_string(format!("../data/keys/clients/{}_ip.txt", uid_bob)).unwrap();
    
    // Prompt for encryption type preference
    print!("Enter encryption type (RSA or ECC): ");
    io::stdout().flush().unwrap(); 

    // Read and parse encryption type choice
    let mut typ = String::new();
    io::stdin().read_line(&mut typ).unwrap();
    let mut typ = typ.trim().to_string();

    // Validate encryption type choice
    if typ != "RSA" && typ != "ECC" {
        eprintln!("❌ Invalid type. Please enter 'RSA' or 'ECC'.");
        return;
    }

    // Ask if the user wants to use a pre-shared symmetric key
    print!("Do you own a symmetric key? (y/n): ");
    io::stdout().flush().unwrap();

    // Read symmetric key choice
    let mut sym_choice = String::new();
    io::stdin().read_line(&mut sym_choice).unwrap();

    // If user has a symmetric key, update encryption type to include AES
    if sym_choice.trim().eq_ignore_ascii_case("y") {
        typ = format!("{}_AES", typ);
    }

    // If not using symmetric encryption, perform key exchange
    if typ != "RSA_AES" && typ != "ECC_AES" {
        // Get a nonce from the server for authentication
        let nonce = server::get_nonce(&uid, &ip_bob).await;
        println!("Nonce: {:?}", nonce);
        
        match nonce {
            Ok(nonce) => {
                // Send signature based on selected encryption type
                match &typ {
                    t if t == "RSA" => {
                        // Sign with RSA and perform key exchange
                        if let Err(e) = server::send_signature_rsa(&uid, &nonce, &ip_bob, uid_bob).await {
                            eprintln!("❌ Error sending signature: {}", e);
                            return;
                        }
                    }
                    t if t == "ECC" => {
                        // Sign with ECC and perform key exchange
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

    // Generate a fresh nonce for the interactive session
    let nonce2 = generate_nonce();
    
    // Start the interactive shell session with the server
    interactive_loop(&uid, &nonce2, &ip_bob, &typ, uid_bob)
        .await
        .unwrap_or_else(|e| {
            eprintln!("❌ Error in interactive loop: {}", e); 
            return;
        });

}
