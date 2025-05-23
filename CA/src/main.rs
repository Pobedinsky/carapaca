use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use serde::{Serialize, Deserialize};

use std::convert::Infallible;
use tokio::runtime::Runtime;

use url::form_urlencoded;


mod signup;
mod loggin;
mod db_service;
mod user;

#[derive(Serialize, Deserialize)]
struct ResponseData {
    message: String,
    status: String,
}

// Function to handle a GET request (200 OK)
async fn handle_get() -> Result<Response<Body>, Infallible> {
    let data = ResponseData {
        message: "Operation successful".to_string(),
        status: "success".to_string(),
    };

    let json_response = serde_json::to_string(&data).unwrap();

    Ok(Response::new(Body::from(json_response)))
}


async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match req.uri().path() {
        "/get" => handle_get().await,
        "/hello-i-was-born" => signup::signup_handler(req).await,
        "/wassap-im-ready" => loggin::handle_update_ip(req).await,
        "/holy-bible" | "/holy-bible/" => signup::handle_get_all().await,
        path if path.starts_with("/holy-bible/") => {
            let query = req.uri().query().unwrap_or(""); // Extract ?nonce=... if present
            let params: std::collections::HashMap<_, _> =
                form_urlencoded::parse(query.as_bytes()).into_owned().collect();

            let nonce = params.get("nonce").cloned().unwrap_or_else(|| "default_nonce".to_string());

            if let Some(uid) = path.strip_prefix("/holy-bible/") {
                signup::handle_get_user(uid.to_string(), nonce).await
            } else {
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


fn main() {
    // Create a runtime to run the async server
    let rt = Runtime::new().unwrap();

    rt.block_on(async {
        // Define the address to bind the server to
        let addr = ([0, 0, 0, 0], 3000).into();

        // Create the service
        let make_svc = make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(handle_request)) });

        // Try to bind the server
        let server = Server::try_bind(&addr)
            .unwrap_or_else(|e| {
                eprintln!("Server bind error: {}", e);
                std::process::exit(1);
            })
            .serve(make_svc);

        println!("Server running on http://{}", addr);

        // Run the server
        if let Err(e) = server.await {
            eprintln!("Server error: {}", e);
        }
    });
}