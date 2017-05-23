extern crate rusoto_core;
extern crate rusoto_dynamodb;

use std::default::Default;
use std::str::FromStr;
use std::error::Error;
use std::convert::From;

use self::rusoto_core::*;
use self::rusoto_dynamodb::{DynamoDb, DynamoDbClient, DescribeTableInput};

struct AWSError {
    message: String
}

impl <A: Error> From<A> for AWSError {
    fn from(err: A) -> AWSError { 
        let message = String::from(err.description());
        AWSError { 
            message
        }
    }
}

struct AWS {
    table_name: String,
    dynamo_client: Box<DynamoDb>
}

impl AWS {

    fn new(profile: Option<String>, region: String, table_name: String) -> Result<AWS, AWSError> {
        let provider = AWS::build_creds_provider(profile)?;
        let reg = Region::from_str(region.as_str())?;
        let tls_client = default_tls_client()?;
        let dynamo_client = Box::new(DynamoDbClient::new(tls_client, provider, reg));
        Ok(AWS {
            table_name,
            dynamo_client
        })
    }

    fn build_creds_provider(profile: Option<String>) -> Result<DefaultCredentialsProvider, CredentialsError> {
        let mut profile_provider = ProfileProvider::new().unwrap();
        if profile.is_some() {
            profile_provider.set_profile(profile.unwrap()); // Rust Option doesn't have a foreach method :(
        }
        let chain_provider = ChainProvider::with_profile_provider(profile_provider);
        AutoRefreshingProvider::with_refcell(chain_provider)
    }

    fn setup(&self) -> Result<bool, AWSError> {
        // TODO create Dynamo table if it does not exist
        self.doesTableExist()
    }

    fn doesTableExist(&self) -> Result<bool, AWSError> {
        let table_name = self.table_name.clone();
        let describe_table_input = DescribeTableInput { table_name };
        let output = self.dynamo_client.describe_table(&describe_table_input)?;
        Ok(output.table.is_some())
    }

}
