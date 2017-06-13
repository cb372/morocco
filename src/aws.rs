extern crate rusoto_core;
extern crate rusoto_dynamodb;
extern crate rusoto_kms;
extern crate base64;


use std::str::FromStr;
use std::default::Default;

use self::rusoto_core::*;
use self::rusoto_dynamodb::*;
use self::rusoto_kms::*;
use self::base64::{encode, decode};

use squirrel::*;
use encryption::*;

struct EncryptionResult {
    encrypted_data_key: Vec<u8>,
    encrypted_data: Vec<u8>,
    iv: Vec<u8>
}

pub struct AWS {
    table_name: String,
    key_alias: String,
    dynamo_client: Box<DynamoDb>,
    kms_client: Box<Kms>
}

// TODO refactor: separate Dynamo stuff and KMS stuff into submodules?
// 275 lines in one file seems excessive.

// TODO implement delete (can't be bothered right now)

// TODO store values as binary when rusoto fix is released

impl Squirrel for AWS {

    fn setup(&self) -> Result<String, SquirrelError> {
        let create_table_result = self.create_table_if_does_not_exist()?;
        let create_key_result = self.create_master_key_if_does_not_exist()?;
        Ok(format!("{} {}", create_table_result, create_key_result))
    }

    fn list(&self) -> Result<Vec<String>, SquirrelError> {
        let scan_input = ScanInput {
            table_name: self.table_name.clone(),
            ..Default::default()
        };
        match self.dynamo_client.scan(&scan_input) {
            Ok(output) => {
                let items = output.items.unwrap_or(Vec::new());
                let ids = items.iter()
                    .flat_map(|item| item.get("id"))
                    .flat_map(|value| value.s.clone())
                    .collect();
                Ok(ids)
            }
            Err(err) => Err(SquirrelError::from(err))
        }
    }

    fn get(&self, id: String) -> Result<Vec<u8>, SquirrelError> {
        let key = [
            ("id".to_string(), AttributeValue { s: Some(id), ..Default::default() })
        ].iter().cloned().collect::<Key>();
        let get_item_input = GetItemInput {
            key: key,
            table_name: self.table_name.clone(),
            ..Default::default()
        };
        match self.dynamo_client.get_item(&get_item_input) {
            Ok(output) => {
                match output.item {
                    Some(item) => self.decrypt_item(&item),
                    None => Err(SquirrelError { message: "No secret found with that id".to_string() })
                }
            }
            Err(err) => Err(SquirrelError::from(err))
        }
    }

    // TODO support --overwrite (don't overwrite existing record unless the overwrite flag is true)
    fn put(&self, id: String, value: Vec<u8>) -> Result<(), SquirrelError> {
        let encryption_result = self.encrypt_value(value)?;
        // store as base64 string instead of binary to work around
        // https://github.com/rusoto/rusoto/issues/658
        let item = [
            ("id".to_string(), AttributeValue { s: Some(id), ..Default::default() }),
            ("encrypted_data_key".to_string(), AttributeValue { s: Some(encode(&encryption_result.encrypted_data_key)), .. Default::default() }),
            ("encrypted_data".to_string(), AttributeValue { s: Some(encode(&encryption_result.encrypted_data)), .. Default::default() }),
            ("iv".to_string(), AttributeValue { s: Some(encode(&encryption_result.iv)), .. Default::default() })
        ].iter().cloned().collect::<PutItemInputAttributeMap>();
        let put_item_input = PutItemInput {
            table_name: self.table_name.clone(),
            item: item,
            ..Default::default()
        };
        match self.dynamo_client.put_item(&put_item_input) {
            Ok(_) => Ok(()),
            Err(err) => Err(SquirrelError::from(err))
        }
    }

}

impl AWS {

    pub fn new(profile: Option<String>, region: String, table_name: String, key_alias: String) -> Result<AWS, SquirrelError> {
        let reg = Region::from_str(region.as_str())?;
        let dynamo_client = DynamoDbClient::new(default_tls_client()?, AWS::build_creds_provider(profile.clone())?, reg);
        let kms_client = KmsClient::new(default_tls_client()?, AWS::build_creds_provider(profile.clone())?, reg);
        Ok(AWS {
            table_name: table_name,
            key_alias: key_alias,
            dynamo_client: Box::new(dynamo_client),
            kms_client: Box::new(kms_client)
        })
    }

    fn encrypt_value(&self, value: Vec<u8>) -> Result<EncryptionResult, SquirrelError> {
        let gen_random_request = GenerateRandomRequest { 
            number_of_bytes: Some(16)
        };
        let iv = self.kms_client.generate_random(&gen_random_request)
            .map(|response| response.plaintext.unwrap())?;

        let key_alias = self.key_alias.clone();
        let key_id = format!("alias/{}", key_alias);
        let gen_data_key_request = GenerateDataKeyRequest {
            key_id: key_id,
            number_of_bytes: Some(32),
            .. Default::default()
        };
        let (encrypted_key, plaintext_key) = self.kms_client.generate_data_key(&gen_data_key_request)
            .map(|response| (response.ciphertext_blob.unwrap(), response.plaintext.unwrap()))?;

        match encrypt(value.as_slice(), 
                       plaintext_key.as_slice(), 
                       iv.as_slice()) {
            Ok(ciphertext) => Ok(EncryptionResult {
                encrypted_data_key: encrypted_key,
                encrypted_data: ciphertext,
                iv: iv
            }),
            Err(_) => Err(SquirrelError { message: "Failed to encrypt secret.".to_string() })
        }
    }

    // TODO refactor this beast
    fn decrypt_item(&self, attribute_map: &AttributeMap) -> Result<Vec<u8>, SquirrelError> {
        let encrypted_key_opt = attribute_map.get("encrypted_data_key").and_then(|x| x.s.clone());
        let encrypted_data_opt = attribute_map.get("encrypted_data").and_then(|x| x.s.clone());
        let iv_opt = attribute_map.get("iv").and_then(|x| x.s.clone());
        match (encrypted_key_opt, encrypted_data_opt, iv_opt) {
            (Some(encrypted_key_base64), Some(encrypted_data_base64), Some(iv_base64)) => {
                let encrypted_key = decode(&encrypted_key_base64)?;
                let encrypted_data = decode(&encrypted_data_base64)?;
                let iv = decode(&iv_base64)?;
                let decrypt_request = DecryptRequest {
                    ciphertext_blob: encrypted_key,
                    ..Default::default()
                };
                match self.kms_client.decrypt(&decrypt_request) {
                    Ok(DecryptResponse { plaintext: Some(plaintext_key), .. }) => {
                        match decrypt(encrypted_data.as_slice(), 
                                      plaintext_key.as_slice(), 
                                      iv.as_slice()) {
                            Ok(plaintext_data) => Ok(plaintext_data),
                            Err(_) => Err(SquirrelError { message: "Failed to decrypt secret".to_string() })
                        }
                    },
                    Ok(_) => Err(SquirrelError { message: "Failed to decrypt the data key".to_string() }),
                    Err(err) => Err(SquirrelError::from(err))
                }
            },
            _ => Err(SquirrelError { message: "Item did not contain the expected fields".to_string() })
        }
    }

    fn build_creds_provider(profile: Option<String>) -> Result<DefaultCredentialsProvider, CredentialsError> {
        let mut profile_provider = ProfileProvider::new().unwrap();
        if let Some(prof) = profile {
            profile_provider.set_profile(prof); // Rust Option doesn't have a foreach method :(
        }
        let chain_provider = ChainProvider::with_profile_provider(profile_provider);
        AutoRefreshingProvider::with_refcell(chain_provider)
    }

    fn does_table_exist(&self) -> Result<bool, SquirrelError> {
        let table_name = self.table_name.clone();
        let describe_table_input = DescribeTableInput { table_name };
        match self.dynamo_client.describe_table(&describe_table_input) {
            Ok(output) => Ok(output.table.is_some()),
            Err(DescribeTableError::ResourceNotFound(_)) => Ok(false),
            Err(other) => Err(SquirrelError::from(other))
        }
    }

    fn create_table(&self) -> Result<(), SquirrelError> {
        let table_name = self.table_name.clone();
        let create_table_input = CreateTableInput { 
            attribute_definitions: vec![ AttributeDefinition { 
                attribute_name: "id".to_string(), 
                attribute_type: "S".to_string() 
            } ],
            key_schema: vec![ KeySchemaElement { 
                attribute_name: "id".to_string(), 
                key_type: "HASH".to_string() 
            } ],
            provisioned_throughput: ProvisionedThroughput { 
                read_capacity_units: 1, 
                write_capacity_units: 1 
            },
            table_name: table_name,
            ..Default::default()
        };
        self.dynamo_client.create_table(&create_table_input)?;
        Ok(())
    }

    fn create_table_if_does_not_exist(&self) -> Result<&str, SquirrelError> {
        if self.does_table_exist()? {
            Ok("Dynamo table already existed.")
        } else {
            self.create_table()?;
            Ok("Created Dynamo table.")
        }
    }

    fn does_master_key_exist(&self) -> Result<bool, SquirrelError> {
        let key_alias = self.key_alias.clone();
        let key_id = format!("alias/{}", key_alias);
        let describe_key_request = DescribeKeyRequest { 
            grant_tokens: None,
            key_id: key_id
        };
        match self.kms_client.describe_key(&describe_key_request) {
            Ok(response) => Ok(response.key_metadata.is_some()),
            Err(DescribeKeyError::NotFound(_)) => Ok(false),
            Err(other) => Err(SquirrelError::from(other))
        }
    }

    fn create_master_key(&self) -> Result<(), SquirrelError> {
        let create_key_request = CreateKeyRequest { 
            description: Some("Master key for encryption of secrets by squirrel".to_string()),
            ..Default::default()
        };
        let create_key_response = self.kms_client.create_key(&create_key_request)?;
        let key_id = create_key_response.key_metadata.unwrap().key_id;

        let alias_name = format!("alias/{}", self.key_alias);
        let create_alias_request = CreateAliasRequest {
            alias_name: alias_name,
            target_key_id: key_id
        };
        let result = self.kms_client.create_alias(&create_alias_request)?;
        Ok(result)
    }

    fn create_master_key_if_does_not_exist(&self) -> Result<&str, SquirrelError> {
        if self.does_master_key_exist()? {
            Ok("Customer master key already existed.")
        } else {
            self.create_master_key()?;
            Ok("Created customer master key.")
        }
    }

}
