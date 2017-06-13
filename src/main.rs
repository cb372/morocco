extern crate clap;

use clap::{Arg, App, SubCommand, ArgMatches};

use std::io::stderr;
use std::io::Write;

mod squirrel;
mod aws;
mod encryption;

use squirrel::{Squirrel, SquirrelError};
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
                         .short("p")
                         .takes_value(true)
                         .help("use custom IAM profile"))
                    .arg(Arg::with_name("region")
                         .short("r")
                         .default_value("eu-west-1")
                         .help("use custom AWS region"))
                    .arg(Arg::with_name("table")
                         .short("t")
                         .default_value("squirrel")
                         .help("use custom DynamoDB table"))
                    .arg(Arg::with_name("key-alias")
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
                                     .short("o")
                                     .default_value("false")
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
                println!("Failed to initialise AWS client. Error: {}", err.message);
                println!("{}", matches.usage())
            }
        }
    } else {
        println!("{}", matches.usage());
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
                Err(e) => writeln!(stderr(), "Failed to set up KMS customer master key and/or Dynamo table! {}", e.message).unwrap()
            }
        },

        ("list", _) => {
            match squirrel.list() {
                Ok(ids) => {
                    for id in ids {
                        println!("{}", id);
                    }
                },
                Err(e) => writeln!(stderr(), "Failed to list secrets! {}", e.message).unwrap()
            }
        },

        ("get", Some(get_matches)) => {
            let id = get_matches.value_of("ID").unwrap().to_string();
            match squirrel.get(id) {
                Ok(value) => println!("{}", String::from_utf8(value).unwrap()),
                Err(e) => println!("Failed to retrieve secret! {}", e.message)
            }
        },

        ("put", Some(put_matches)) => {
            let id = put_matches.value_of("ID").unwrap().to_string();
            let value = put_matches.value_of("VALUE").unwrap().as_bytes().to_vec();
            // TODO support --overwrite
            match squirrel.put(id, value) {
                Ok(_) => println!("Stored secret."),
                Err(e) => println!("Failed to store secret! {}", e.message)
            }
        },

        // TODO support delete
        
        _ => println!("{}", matches.usage())
    }
}
