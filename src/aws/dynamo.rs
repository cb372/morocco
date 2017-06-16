extern crate rusoto_dynamodb;
extern crate base64;

use morocco::{MoroccoError, PutResult, DeletionResult};
use aws::Item;

use self::rusoto_dynamodb::*;
use self::base64::{encode, decode};

pub struct DynamoOps {
    table_name: String,
    dynamo_client: Box<DynamoDb>
}

impl DynamoOps {

    pub fn new(table_name: String, dynamo_client: Box<DynamoDb>) -> DynamoOps {
        DynamoOps {
            table_name: table_name,
            dynamo_client: dynamo_client
        }
    }

    pub fn list_ids(&self) -> Result<Vec<String>, MoroccoError> {
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
            Err(err) => Err(MoroccoError::from(err))
        }
    }

    pub fn get_item(&self, id: String) -> Result<Item, MoroccoError> {
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
                    Some(attr_map) => attribute_map_to_item(&attr_map),
                    None => Err(MoroccoError { message: "No secret found with that ID.".to_string() })
                }
            }
            Err(err) => Err(MoroccoError::from(err))
        }
    }

    pub fn put_item(&self, id: String, item: Item, overwrite: bool) -> Result<PutResult, MoroccoError> {
        // store as base64 string instead of binary to work around
        // https://github.com/rusoto/rusoto/issues/658
        let attributes = [
            ("id".to_string(), 
             AttributeValue { s: Some(id), ..Default::default() }),

            ("encrypted_data_key".to_string(), 
             AttributeValue { s: Some(encode(&item.encrypted_data_key)), .. Default::default() }),

            ("encrypted_data".to_string(), 
             AttributeValue { s: Some(encode(&item.encrypted_data)), .. Default::default() }),

            ("iv".to_string(), 
             AttributeValue { s: Some(encode(&item.iv)), .. Default::default() })
        ].iter().cloned().collect::<PutItemInputAttributeMap>();

        let condition_expr =
            if overwrite { None } else { Some("attribute_not_exists(id)".to_string()) };

        let put_item_input = PutItemInput {
            table_name: self.table_name.clone(),
            item: attributes,
            condition_expression: condition_expr,
            ..Default::default()
        };

        match self.dynamo_client.put_item(&put_item_input) {
            Ok(_) => Ok(PutResult::Stored),
            Err(PutItemError::ConditionalCheckFailed(_)) => Ok(PutResult::DidNotOverwrite),
            Err(err) => Err(MoroccoError::from(err))
        }
    }

    pub fn delete_item(&self, id: String) -> Result<DeletionResult, MoroccoError> {
        let key = [
            ("id".to_string(), AttributeValue { s: Some(id), ..Default::default() })
        ].iter().cloned().collect::<Key>();
        let delete_item_input = DeleteItemInput {
            key: key,
            table_name: self.table_name.clone(),
            condition_expression: Some("attribute_exists(id)".to_string()),
            ..Default::default()
        };
        match self.dynamo_client.delete_item(&delete_item_input) {
            Ok(_) => Ok(DeletionResult::Deleted),
            Err(DeleteItemError::ConditionalCheckFailed(_)) => Ok(DeletionResult::NotFound),
            Err(err) => Err(MoroccoError::from(err))
        }
    }

    pub fn create_table_if_does_not_exist(&self) -> Result<&str, MoroccoError> {
        if self.does_table_exist()? {
            Ok("Dynamo table already existed.")
        } else {
            self.create_table()?;
            Ok("Created Dynamo table.")
        }
    }

    fn does_table_exist(&self) -> Result<bool, MoroccoError> {
        let table_name = self.table_name.clone();
        let describe_table_input = DescribeTableInput { table_name };
        match self.dynamo_client.describe_table(&describe_table_input) {
            Ok(output) => Ok(output.table.is_some()),
            Err(DescribeTableError::ResourceNotFound(_)) => Ok(false),
            Err(other) => Err(MoroccoError::from(other))
        }
    }

    fn create_table(&self) -> Result<(), MoroccoError> {
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

}

fn attribute_map_to_item(attribute_map: &AttributeMap) -> Result<Item, MoroccoError> {
    let encrypted_key_opt = attribute_map.get("encrypted_data_key").and_then(|x| x.s.clone());
    let encrypted_data_opt = attribute_map.get("encrypted_data").and_then(|x| x.s.clone());
    let iv_opt = attribute_map.get("iv").and_then(|x| x.s.clone());

    match (encrypted_key_opt, encrypted_data_opt, iv_opt) {
        (Some(encrypted_key_base64), Some(encrypted_data_base64), Some(iv_base64)) => {
            let encrypted_key = decode(&encrypted_key_base64)?;
            let encrypted_data = decode(&encrypted_data_base64)?;
            let iv = decode(&iv_base64)?;
            Ok(Item {
                encrypted_data_key: encrypted_key,
                encrypted_data: encrypted_data,
                iv: iv
            })
        },
        _ => Err(MoroccoError { message: "Item did not contain the expected fields".to_string() })
    }
}

