extern crate rusoto_core;
extern crate rusoto_dynamodb;
extern crate rusoto_kms;

use std::str::FromStr;
use std::error::Error;
use std::convert::From;

use self::rusoto_core::*;
use self::rusoto_dynamodb::*;
use self::rusoto_kms::*;

pub struct AWSError {
    pub message: String
}

impl <A: Error> From<A> for AWSError {
    fn from(err: A) -> AWSError { 
        let message = String::from(err.description());
        AWSError { 
            message
        }
    }
}

pub struct AWS {
    table_name: String,
    key_alias: String,
    dynamo_client: Box<DynamoDb>,
    kms_client: Box<Kms>
}

impl AWS {

    pub fn new(profile: Option<String>, region: String, table_name: String, key_alias: String) -> Result<AWS, AWSError> {
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

    pub fn setup(&self) -> Result<String, AWSError> {
        let create_table_result = self.create_table_if_does_not_exist()?;
        let create_key_result = self.create_master_key_if_does_not_exist()?;
        Ok(format!("{} {}", create_table_result, create_key_result))
    }

    fn build_creds_provider(profile: Option<String>) -> Result<DefaultCredentialsProvider, CredentialsError> {
        let mut profile_provider = ProfileProvider::new().unwrap();
        if profile.is_some() {
            profile_provider.set_profile(profile.unwrap()); // Rust Option doesn't have a foreach method :(
        }
        let chain_provider = ChainProvider::with_profile_provider(profile_provider);
        AutoRefreshingProvider::with_refcell(chain_provider)
    }

    fn does_table_exist(&self) -> Result<bool, AWSError> {
        let table_name = self.table_name.clone();
        let describe_table_input = DescribeTableInput { table_name };
        match self.dynamo_client.describe_table(&describe_table_input) {
            Ok(output) => Ok(output.table.is_some()),
            Err(DescribeTableError::ResourceNotFound(_)) => Ok(false),
            Err(other) => Err(AWSError::from(other))
        }
    }

    fn create_table(&self) -> Result<(), AWSError> {
        let table_name = self.table_name.clone();
        let create_table_input = CreateTableInput { 
            attribute_definitions: vec![ AttributeDefinition { 
                attribute_name: "name".to_string(), 
                attribute_type: "S".to_string() 
            } ],
            global_secondary_indexes: None,
            key_schema: vec![ KeySchemaElement { 
                attribute_name: "name".to_string(), 
                key_type: "HASH".to_string() 
            } ],
            local_secondary_indexes: None,
            provisioned_throughput: ProvisionedThroughput { 
                read_capacity_units: 1, 
                write_capacity_units: 1 
            },
            stream_specification: None,
            table_name: table_name
        };
        self.dynamo_client.create_table(&create_table_input)?;
        Ok(())
    }

    fn create_table_if_does_not_exist(&self) -> Result<&str, AWSError> {
        if self.does_table_exist()? {
            Ok("Dynamo table already existed.")
        } else {
            self.create_table()?;
            Ok("Created Dynamo table.")
        }
    }

    fn does_master_key_exist(&self) -> Result<bool, AWSError> {
        let key_alias = self.key_alias.clone();
        let key_id = format!("alias/{}", key_alias);
        let describe_key_request = DescribeKeyRequest { 
            grant_tokens: None,
            key_id: key_id
        };
        match self.kms_client.describe_key(&describe_key_request) {
            Ok(response) => Ok(response.key_metadata.is_some()),
            Err(DescribeKeyError::NotFound(_)) => Ok(false),
            Err(other) => Err(AWSError::from(other))
        }
    }

    fn create_master_key(&self) -> Result<(), AWSError> {
        let create_key_request = CreateKeyRequest { 
            bypass_policy_lockout_safety_check: None,
            description: Some("Master key for encryption of secrets by squirrel".to_string()),
            key_usage: None,
            origin: None,
            policy: None
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

    fn create_master_key_if_does_not_exist(&self) -> Result<&str, AWSError> {
        if self.does_master_key_exist()? {
            Ok("Customer master key already existed.")
        } else {
            self.create_master_key()?;
            Ok("Created customer master key.")
        }
    }

}
