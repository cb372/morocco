extern crate rusoto_core;
extern crate rusoto_dynamodb;

use std::str::FromStr;
use std::error::Error;
use std::convert::From;

use self::rusoto_core::*;
use self::rusoto_dynamodb::*;

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
    dynamo_client: Box<DynamoDb>
}

impl AWS {

    pub fn new(profile: Option<String>, region: String, table_name: String) -> Result<AWS, AWSError> {
        let provider = AWS::build_creds_provider(profile)?;
        let reg = Region::from_str(region.as_str())?;
        let tls_client = default_tls_client()?;
        let dynamo_client = Box::new(DynamoDbClient::new(tls_client, provider, reg));
        Ok(AWS {
            table_name,
            dynamo_client
        })
    }

    pub fn setup(&self) -> Result<bool, AWSError> {
        if self.does_table_exist()? {
            Ok(false)
        } else {
            self.create_table()?;
            Ok(true)
        }
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


}
