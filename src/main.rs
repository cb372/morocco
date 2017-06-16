extern crate clap;

use clap::{Arg, App, SubCommand, ArgMatches};

use std::io::stderr;
use std::io::Write;
use std::process::exit;

mod squirrel;
mod aws;
mod encryption;

use squirrel::*;
use aws::AWS;

// Examples of valid commands:
// squirrel aws setup
// squirrel aws list
// squirrel aws get my.secret
// squirrel aws put my.secret "oh my god"
// squirrel aws put --overwrite my.secret "oh my god"
// squirrel aws delete my.secret
// squirrel aws --profile foo --region eu-west-1 --table my-custom-table list
// TODO similar commands for GCP


fn main() {
    let matches = App::new("squirrel")
        .version("0.1.0")
        .about("Secure secret management in the cloud")
        .subcommand(SubCommand::with_name("aws")
                    .about("Use Amazon's Key Management Service for encryption and DynamoDB for storage")
                    .arg(Arg::with_name("profile")
                         .long("profile")
                         .short("p")
                         .takes_value(true)
                         .help("use custom IAM profile"))
                    .arg(Arg::with_name("region")
                         .long("region")
                         .short("r")
                         .default_value("eu-west-1")
                         .help("use custom AWS region"))
                    .arg(Arg::with_name("table")
                         .long("table")
                         .short("t")
                         .default_value("squirrel")
                         .help("use custom DynamoDB table"))
                    .arg(Arg::with_name("key-alias")
                         .long("key-alias")
                         .short("k")
                         .default_value("squirrel")
                         .help("use custom KMS customer master key"))
                    .subcommand(SubCommand::with_name("setup"))
                    .subcommand(SubCommand::with_name("list"))
                    .subcommand(SubCommand::with_name("get")
                                .arg(Arg::with_name("ID")
                                     .required(true)
                                     .index(1)))
                    .subcommand(SubCommand::with_name("put")
                                .arg(Arg::with_name("overwrite")
                                     .long("overwrite")
                                     .short("o")
                                     .takes_value(false)
                                     .help("overwrite the record if it already exists"))
                                .arg(Arg::with_name("ID")
                                     .required(true)
                                     .index(1))
                                .arg(Arg::with_name("VALUE")
                                     .required(true)
                                     .index(2)))
                    .subcommand(SubCommand::with_name("delete")
                                .arg(Arg::with_name("ID")
                                     .required(true)
                                     .index(1)))
         )
        .get_matches();

    if let Some(aws_matches) = matches.subcommand_matches("aws") {
        match construct_aws(aws_matches) {
            Ok(aws) => run_subcommand(aws, aws_matches),
            Err(err) => {
                bail(format!("Failed to initialise AWS client. Error: {}\n{}", err.message, matches.usage()));
            }
        }
    } else {
        bail(matches.usage().to_string());
    }
    
}

fn construct_aws(matches: &ArgMatches) -> Result<AWS, SquirrelError> {
    let profile = matches.value_of("profile").map(|s| s.to_string());
    let region = matches.value_of("region").unwrap().to_string();
    let table = matches.value_of("table").unwrap().to_string();
    let key_alias = matches.value_of("key-alias").unwrap().to_string();
    aws::AWS::new(profile, region, table, key_alias)
}

fn run_subcommand<S: Squirrel>(squirrel: S, matches: &ArgMatches) {
    match matches.subcommand() {
        ("setup", _) => {
            match squirrel.setup() {
                Ok(result) => println!("Set up complete. {}", result),
                Err(e) => bail(format!("Failed to set up KMS customer master key and/or Dynamo table! {}", e.message))
            }
        },

        ("list", _) => {
            match squirrel.list() {
                Ok(ids) => {
                    for id in ids {
                        println!("{}", id);
                    }
                },
                Err(e) => bail(format!("Failed to list secrets! {}", e.message))
            }
        },

        ("get", Some(get_matches)) => {
            let id = get_matches.value_of("ID").unwrap().to_string();
            match squirrel.get(id) {
                Ok(value) => println!("{}", String::from_utf8(value).unwrap()),
                Err(e) => bail(format!("Failed to retrieve secret! {}", e.message))
            }
        },

        ("put", Some(put_matches)) => {
            let id = put_matches.value_of("ID").unwrap().to_string();
            let value = put_matches.value_of("VALUE").unwrap().as_bytes().to_vec();
            let overwrite = put_matches.is_present("overwrite");
            match squirrel.put(id, value, overwrite) {
                Ok(PutResult::Stored) => println!("Stored secret."),
                Ok(PutResult::DidNotOverwrite) => bail(format!("Failed to store secret! It was already present. If you want to overwrite the existing value, please use the --overwrite option.")),
                Err(e) => bail(format!("Failed to store secret! {}", e.message))
            }
        },

        ("delete", Some(get_matches)) => {
            let id = get_matches.value_of("ID").unwrap().to_string();
            match squirrel.delete(id) {
                Ok(DeletionResult::Deleted) => println!("{}", "Deleted secret."),
                Ok(DeletionResult::NotFound) => bail(format!("Failed to delete secret! No secret found with that ID.")),
                Err(e) => bail(format!("Failed to delete secret! {}", e.message))
            }
        },

        
        _ => bail(matches.usage().to_string())
    }
}

fn bail(message: String) {
    writeln!(stderr(), "{}", message).unwrap();
    exit(1)
}
