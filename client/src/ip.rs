use reqwest;

pub async fn get_public_ip() -> Result<String, reqwest::Error> {
    let ip = reqwest::get("https://api.ipify.org")
        .await?
        .text()
        .await?;
    Ok(ip)
}
