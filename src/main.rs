extern crate clap;

use clap::{Arg, App, SubCommand};

// Examples of valid commands:
// squirrel aws setup
// squirrel aws list
// squirrel aws get my.secret
// squirrel aws put my.secret "oh my god"
// squirrel aws delete my.secret
// squirrel aws --profile foo --region eu-west-1 --table my-custom-table list
// TODO research GCP more thoroughly

mod aws;

fn main() {
    App::new("squirrel")
        .version("0.1.0")
        .about("Secure secret management in the cloud")
        .author("Chris Birchall")
        .subcommand(SubCommand::with_name("aws")
                    .about("Use Amazon's Key Management Service for encryption and DynamoDB for storage")
                    .arg(Arg::with_name("profile")
                         .short("p")
                         .help("use custom IAM profile"))
                    .arg(Arg::with_name("region")
                         .short("r")
                         .default_value("eu-west-1")
                         .help("use custom AWS region"))
                    .arg(Arg::with_name("table")
                         .short("t")
                         .default_value("squirrel")
                         .help("use custom DynamoDB table"))
                    .subcommand(SubCommand::with_name("setup"))
                    .subcommand(SubCommand::with_name("list"))
                    // TODO remaining subcommands
         )
        .get_matches();

    // TODO this is just an example, we are ignoring the command line for now
    
    let aws = aws::AWS::new(None, "eu-west-1".to_string(), "squirrel".to_string());
    match aws {
        Ok(a) => {
            match a.setup() {
                Ok(result) => println!("Set up {}", result),
                Err(e) => println!("Failed to set up Dynamo table! {}", e.message)
            }
            
        },
        Err(e) => println!("Failed to set up AWS client! {}", e.message)
    }
    
}
