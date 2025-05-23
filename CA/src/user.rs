// User Data Structure Module
// This file defines the User structure for storing user information in the Certificate Authority
// It contains all essential user data including identifiers, public keys, and network information
use serde::{Deserialize, Serialize};

// User structure representing a registered user in the Certificate Authority system
// This structure is used for database storage and JSON serialization/deserialization
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub uid: String,     // Unique user identifier
    pub pk_rsa: String,  // RSA public key in PEM format for asymmetric encryption/signing
    pub pk_ecc: String,  // ECC public key in PEM format for elliptic curve operations
    pub ip: String,      // User's current IP address for network communication
}