use firestore::{paths, FirestoreDb, FirestoreDbOptions};
use firestore::errors::FirestoreError;
use crate::user::User;
use std::collections::BTreeMap;
use serde_json::json;

pub struct DbService {
    client: FirestoreDb
}
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct UserIpUpdate {
    ip: String,
}

impl DbService{
    pub async fn new() -> DbService {
        DbService{
            client: FirestoreDb::with_options_service_account_key_file(
                FirestoreDbOptions::new(String::from("carapaca-6170c")),
                "src/data/service.json".parse().unwrap()
            ).await.unwrap()
        }        
    }

    pub async fn insert(&self, user: User) -> Result<(), FirestoreError> {
        println!("A inserior user: {:?}", user);

        self
            .client
            .fluent()
            .insert()
            .into("Users")
            .document_id(&user.uid)
            .object(&user)
            .execute::<()>()
            .await?;
        
        Ok(())
    }

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
    
    



pub async fn update_user_ip(&self, uid: String, new_ip: String) -> Result<(), FirestoreError> {
    let mut update_map = BTreeMap::new();
    update_map.insert("ip".to_string(), json!(new_ip));

    self.client
        .fluent()
        .update()
        .fields(paths!(User::ip))  // <-- This must come BEFORE .document_id
        .in_col("Users")
        .document_id(&uid)
        .object(&update_map) 
        
        .execute::<()>()
        .await?;

    Ok(())
}
}
