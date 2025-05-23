/**
 * Shell Command Execution Module
 * 
 * This module provides functions to execute shell commands on a remote execution
 * server via HTTP requests. It handles command forwarding, response parsing, and
 * error handling.
 */

use reqwest::Client;                // HTTP client for API calls
use serde::{Deserialize, Serialize}; // JSON serialization/deserialization

/**
 * Represents a shell command execution request
 * 
 * This structure is serialized to JSON and sent to the shell execution server.
 */
#[derive(Serialize)]
struct ShellRequest {
    uid: String,  // User identifier for authentication and logging
    cmd: String,  // Command to execute on the server
}

/**
 * Represents a response from the shell execution server
 * 
 * Contains the possible response types from the shell server:
 * - output: Successful command execution with output
 * - message: Informational message from the server
 * - error: Error message if command execution failed
 */
#[derive(Deserialize)]
struct ShellResponse {
    output: Option<String>,   // Command execution output
    message: Option<String>,  // Informational message
    error: Option<String>,    // Error message if the command failed
}


/**
 * Execute a command on the remote shell server
 * 
 * This function sends a command to the shell execution server via HTTP POST
 * and processes the response. It handles authentication, error handling, and
 * response parsing.
 * 
 * @param uid - User identifier for authentication
 * @param cmd - Command to execute on the remote server
 * @return Result<String, String> - Command output or error message
 */
pub async fn execute_remote_command(
    uid: &str,
    cmd: &str,
) -> Result<String, String> {
    // Create HTTP client
    let client = Client::new();

    // Prepare request payload with user ID and command
    let request = ShellRequest {
        uid: uid.to_string(),
        cmd: cmd.to_string(),
    };

    // Send POST request to shell execution server
    let res = client
        .post("http://127.0.0.1:8000/execute")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Error sending request: {}", e))?;

    // Parse JSON response
    let response: ShellResponse = res
        .json()
        .await
        .map_err(|e| format!("Error reading response: {}", e))?;

    // Process the response based on the field that is present
    if let Some(output) = response.output {
        // Command executed successfully, return the output
        Ok(output)
    } else if let Some(message) = response.message {
        // Server sent an informational message
        Ok(message)
    } else if let Some(error) = response.error {
        // Server reported an error
        Err(error)
    } else {
        // No recognized fields in the response
        Err("Empty response from server".to_string())
    }
}