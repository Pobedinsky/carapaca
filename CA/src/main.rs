// Certificate Authority (CA) Main Server Implementation
// This file implements the HTTP server for the Certificate Authority
// It handles routing for user registration, authentication, and certificate management
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use serde::{Serialize, Deserialize};

use std::convert::Infallible;
use tokio::runtime::Runtime;

use url::form_urlencoded;


// Import modules for different CA operations
mod signup;    // User registration and certificate issuance
mod loggin;    // Authentication and IP address updates
mod db_service; // Database interactions
mod user;      // User data structures

// Standard response structure for HTTP responses
#[derive(Serialize, Deserialize)]
struct ResponseData {
    message: String,
    status: String,
}

// Function to handle a simple GET request (health check endpoint)
// Returns a successful JSON response indicating the server is operational
async fn handle_get() -> Result<Response<Body>, Infallible> {
    let data = ResponseData {
        message: "Operation successful".to_string(),
        status: "success".to_string(),
    };

    let json_response = serde_json::to_string(&data).unwrap();

    Ok(Response::new(Body::from(json_response)))
}


// Main request handler that routes incoming HTTP requests to appropriate handlers
// This function examines the request path and delegates to specific handlers
async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match req.uri().path() {
        // Health check endpoint
        "/get" => handle_get().await,
        
        // User registration endpoint - handles new user certificate requests
        "/hello-i-was-born" => signup::signup_handler(req).await,
        
        // IP address update endpoint - allows users to update their IP addresses
        "/wassap-im-ready" => loggin::handle_update_ip(req).await,
        
        // Get all registered users endpoint
        "/holy-bible" | "/holy-bible/" => signup::handle_get_all().await,
        
        // Get specific user information endpoint with nonce parameter
        path if path.starts_with("/holy-bible/") => {
            // Extract query parameters (specifically nonce for security)
            let query = req.uri().query().unwrap_or(""); // Extract ?nonce=... if present
            let params: std::collections::HashMap<_, _> =
                form_urlencoded::parse(query.as_bytes()).into_owned().collect();

            let nonce = params.get("nonce").cloned().unwrap_or_else(|| "default_nonce".to_string());

            // Extract user ID from the path and handle the request
            if let Some(uid) = path.strip_prefix("/holy-bible/") {
                signup::handle_get_user(uid.to_string(), nonce).await
            } else {
                // Invalid UID format
                let not_found_data = ResponseData {
                    message: "Invalid UID".to_string(),
                    status: "error".to_string(),
                };
                let json_response = serde_json::to_string(&not_found_data).unwrap();

                Ok(Response::builder()
                    .status(400)
                    .body(Body::from(json_response))
                    .unwrap())
            }
        }
        
        // Handle unknown routes with 404 error
        _ => {
            let not_found_data = ResponseData {
                message: "Route not found".to_string(),
                status: "error".to_string(),
            };
            let json_response = serde_json::to_string(&not_found_data).unwrap();

            Ok(Response::builder()
                .status(404)
                .body(Body::from(json_response))
                .unwrap())
        }
    }
}


// Main function - Entry point for the Certificate Authority server
fn main() {
    // Create a runtime to run the async server
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        // Define the address to bind the server to (0.0.0.0:3000 for all interfaces)
        let addr = ([0, 0, 0, 0], 3000).into();

        // Create the service factory for handling requests
        let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle_request)) });

        // Try to bind the server to the specified address
        let server = Server::try_bind(&addr)
            .unwrap_or_else(|e| {
                eprintln!("Server bind error: {}", e);
                std::process::exit(1);
            })
            .serve(make_svc);

        println!("Server running on http://{}", addr);

        // Run the server and handle any errors
        if let Err(e) = server.await {
            eprintln!("Server error: {}", e);
        }
    });
}