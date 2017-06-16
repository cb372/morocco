extern crate rusoto_core;
extern crate rusoto_kms;
extern crate rusoto_dynamodb;

use std::str::FromStr;

use self::rusoto_core::*;
use self::rusoto_dynamodb::DynamoDbClient;
use self::rusoto_kms::KmsClient;

use morocco::*;
use encryption::*;

mod kms;
mod dynamo;

use aws::kms::KmsOps;
use aws::dynamo::DynamoOps;

pub struct Item {
    encrypted_data_key: Vec<u8>,
    encrypted_data: Vec<u8>,
    iv: Vec<u8>
}

pub struct AWS {
    dynamo_ops: DynamoOps,
    kms_ops: KmsOps
}

// TODO store values as binary when rusoto fix is released

impl Morocco for AWS {

    fn setup(&self) -> Result<String, MoroccoError> {
        let create_table_result = self.dynamo_ops.create_table_if_does_not_exist()?;
        let create_key_result = self.kms_ops.create_master_key_if_does_not_exist()?;
        Ok(format!("{} {}", create_table_result, create_key_result))
    }

    fn list(&self) -> Result<Vec<String>, MoroccoError> {
        self.dynamo_ops.list_ids()
    }

    fn get(&self, id: String) -> Result<Vec<u8>, MoroccoError> {
        let item = self.dynamo_ops.get_item(id)?;
        self.decrypt_item(item)
    }

    fn put(&self, id: String, value: Vec<u8>, overwrite: bool) -> Result<PutResult, MoroccoError> {
        let item = self.encrypt_value(value)?;
        self.dynamo_ops.put_item(id, item, overwrite)
    }

    fn delete(&self, id: String) -> Result<DeletionResult, MoroccoError> {
        self.dynamo_ops.delete_item(id)
    }

}

impl AWS {

    pub fn new(profile: Option<String>, region: String, table_name: String, key_alias: String) -> Result<AWS, MoroccoError> {
        let reg = Region::from_str(region.as_str())?;

        let dynamo_client = DynamoDbClient::new(default_tls_client()?, AWS::build_creds_provider(profile.clone())?, reg);
        let dynamo_ops = DynamoOps::new(table_name.clone(), Box::new(dynamo_client));

        let kms_client = KmsClient::new(default_tls_client()?, AWS::build_creds_provider(profile.clone())?, reg);
        let kms_ops = KmsOps::new(key_alias.clone(), Box::new(kms_client));

        Ok(AWS {
            dynamo_ops: dynamo_ops,
            kms_ops: kms_ops
        })
    }

    fn build_creds_provider(profile: Option<String>) -> Result<DefaultCredentialsProvider, CredentialsError> {
        let mut profile_provider = ProfileProvider::new().unwrap();
        if let Some(prof) = profile {
            profile_provider.set_profile(prof);
        }
        let chain_provider = ChainProvider::with_profile_provider(profile_provider);
        AutoRefreshingProvider::with_refcell(chain_provider)
    }

    fn encrypt_value(&self, value: Vec<u8>) -> Result<Item, MoroccoError> {
        let iv = self.kms_ops.generate_iv()?;
        let data_key = self.kms_ops.generate_data_key()?;

        match encrypt(value.as_slice(), 
                       data_key.plaintext.as_slice(), 
                       iv.as_slice()) {
            Ok(ciphertext) => Ok(Item {
                encrypted_data_key: data_key.encrypted,
                encrypted_data: ciphertext,
                iv: iv
            }),
            Err(_) => Err(MoroccoError { message: "Failed to encrypt secret.".to_string() })
        }
    }

    fn decrypt_item(&self, item: Item) -> Result<Vec<u8>, MoroccoError> {
        let plaintext_key = self.kms_ops.decrypt_data_key(item.encrypted_data_key)?;
        match decrypt(item.encrypted_data.as_slice(), 
                      plaintext_key.as_slice(), 
                      item.iv.as_slice()) {
            Ok(plaintext_data) => Ok(plaintext_data),
            Err(_) => Err(MoroccoError { message: "Failed to decrypt secret".to_string() })
        }
    }

}
