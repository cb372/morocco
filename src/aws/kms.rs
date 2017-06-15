extern crate rusoto_kms;

use squirrel::SquirrelError;

use self::rusoto_kms::*;

pub struct KmsOps {
    key_id: String,
    kms_client: Box<Kms>
}

pub struct DataKey {
    pub encrypted: Vec<u8>,
    pub plaintext: Vec<u8>
}

impl KmsOps {

    pub fn new(key_alias: String, kms_client: Box<Kms>) -> KmsOps {
        KmsOps {
            key_id: format!("alias/{}", key_alias),
            kms_client: kms_client
        }
    }

    pub fn does_master_key_exist(&self) -> Result<bool, SquirrelError> {
        let describe_key_request = DescribeKeyRequest { 
            grant_tokens: None,
            key_id: self.key_id.clone()
        };
        match self.kms_client.describe_key(&describe_key_request) {
            Ok(response) => Ok(response.key_metadata.is_some()),
            Err(DescribeKeyError::NotFound(_)) => Ok(false),
            Err(other) => Err(SquirrelError::from(other))
        }
    }

    pub fn create_master_key(&self) -> Result<(), SquirrelError> {
        let create_key_request = CreateKeyRequest { 
            description: Some("Master key for encryption of secrets by squirrel".to_string()),
            ..Default::default()
        };
        let create_key_response = self.kms_client.create_key(&create_key_request)?;
        let key_id = create_key_response.key_metadata.unwrap().key_id;

        let create_alias_request = CreateAliasRequest {
            alias_name: self.key_id.clone(),
            target_key_id: key_id
        };
        let result = self.kms_client.create_alias(&create_alias_request)?;
        Ok(result)
    }

    pub fn create_master_key_if_does_not_exist(&self) -> Result<&str, SquirrelError> {
        if self.does_master_key_exist()? {
            Ok("Customer master key already existed.")
        } else {
            self.create_master_key()?;
            Ok("Created customer master key.")
        }
    }

    pub fn generate_iv(&self) -> Result<Vec<u8>, SquirrelError> {
        let gen_random_request = GenerateRandomRequest { 
            number_of_bytes: Some(16)
        };
        let iv = self.kms_client.generate_random(&gen_random_request)
            .map(|response| response.plaintext.unwrap())?;
        Ok(iv)
    }

    pub fn generate_data_key(&self) -> Result<DataKey, SquirrelError> {
        let gen_data_key_request = GenerateDataKeyRequest {
            key_id: self.key_id.clone(),
            number_of_bytes: Some(32),
            .. Default::default()
        };
        let (encrypted_key, plaintext_key) = self.kms_client.generate_data_key(&gen_data_key_request)
            .map(|response| (response.ciphertext_blob.unwrap(), response.plaintext.unwrap()))?;
        Ok(DataKey { 
            encrypted: encrypted_key,
            plaintext: plaintext_key
        })
    }

    pub fn decrypt_data_key(&self, encrypted_key: Vec<u8>) -> Result<Vec<u8>, SquirrelError> {
        let decrypt_request = DecryptRequest {
            ciphertext_blob: encrypted_key,
            ..Default::default()
        };
        match self.kms_client.decrypt(&decrypt_request) {
            Ok(DecryptResponse { plaintext: Some(plaintext_key), .. }) => Ok(plaintext_key),
            Ok(_) => Err(SquirrelError { message: "Failed to decrypt the data key".to_string() }),
            Err(err) => Err(SquirrelError::from(err))
        }
    }

}
