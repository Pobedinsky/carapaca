use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub uid: String,
    pub pk_rsa: String,
    pub pk_ecc: String,
    pub ip: String,
}