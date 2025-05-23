// Database Service Module
// This file provides functionality for interacting with Google Firestore database
// It handles user data persistence and retrieval for the Certificate Authority
use firestore::{paths, FirestoreDb, FirestoreDbOptions};
use firestore::errors::FirestoreError;
use crate::user::User;
use std::collections::BTreeMap;
use serde_json::json;

// Main database service structure that holds the connection to Firestore
pub struct DbService {
    client: FirestoreDb
}
use serde::{Serialize, Deserialize};

// Structure for updating just the IP address of a user
#[derive(Serialize, Deserialize)]
struct UserIpUpdate {
    ip: String,
}

impl DbService{
    // Creates a new instance of the database service
    // Establishes connection to Firestore with the project ID "carapaca-6170c"
    pub async fn new() -> DbService {
        DbService{
            client: FirestoreDb::with_options_service_account_key_file(
                FirestoreDbOptions::new(String::from("carapaca-6170c")),
                "src/data/service.json".parse().unwrap()
            ).await.unwrap()
        }        
    }

    // Inserts a new user into the Firestore database
    // The document ID in the "Users" collection will be the user's UID
    pub async fn insert(&self, user: User) -> Result<(), FirestoreError> {
        println!("A inserior user: {:?}", user);

        self
            .client
            .fluent()
            .insert()
            .into("Users")
            .document_id(&user.uid)
            .object(&user)
            .execute::<()>
            .await?;
        
        Ok(())
    }

    // Retrieves all users from the database
    // Returns a vector of User objects
    pub async fn get_all(&self) -> Result<Vec<User>, FirestoreError> {
        let users  = self
            .client
            .fluent()
            .select()
            .from("Users")
            .obj()
            .query()
            .await?;

        Ok(users)
    }

    /* 
    // Currently disabled: Deletes a user by their ID
    pub async fn delete_by_id(&self, id: String) -> Result<(), FirestoreError> {
        self
            .client
            .fluent()
            .delete()
            .from("Users")
            .document_id(&id)
            .execute()
            .await?;
        
        Ok(())
    }
    */

    // Fetches a single user by their UID
    // Returns Option<User> which will be None if the user doesn't exist
    pub async fn get_user(&self, uid: String) -> Result<Option<User>, FirestoreError> {
        let user = self
            .client
            .fluent()
            .select()
            .by_id_in("Users")
            .obj::<User>()
            .one(&uid)
            .await?;
 
        Ok(user)
    }
    
    


// Updates a user's IP address in the database
// Only modifies the IP field, leaving other user data unchanged
pub async fn update_user_ip(&self, uid: String, new_ip: String) -> Result<(), FirestoreError> {
    let mut update_map = BTreeMap::new();
    update_map.insert("ip".to_string(), json!(new_ip));

    self.client
        .fluent()
        .update()
        .fields(paths!(User::ip))  // Specifies that only the IP field should be updated
        .in_col("Users")
        .document_id(&uid)
        .object(&update_map) 
        
        .execute::<()>
        .await?;

    Ok(())
}
}
