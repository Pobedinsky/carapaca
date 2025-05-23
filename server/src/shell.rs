use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct ShellRequest {
    uid: String,
    cmd: String,
}

#[derive(Deserialize)]
struct ShellResponse {
    output: Option<String>,
    message: Option<String>,
    error: Option<String>,
}


pub async fn execute_remote_command(
    uid: &str,
    cmd: &str,
) -> Result<String, String> {
    let client = Client::new();

    let request = ShellRequest {
        uid: uid.to_string(),
        cmd: cmd.to_string(),
    };

    let res = client
        .post("http://127.0.0.1:8000/execute")
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Erro ao enviar requisição: {}", e))?;

    let response: ShellResponse = res
        .json()
        .await
        .map_err(|e| format!("Erro ao ler resposta: {}", e))?;

    if let Some(output) = response.output {
        Ok(output)
    } else if let Some(message) = response.message {
        Ok(message)
    } else if let Some(error) = response.error {
        Err(error)
    } else {
        Err("Resposta vazia do servidor".to_string())
    }
}