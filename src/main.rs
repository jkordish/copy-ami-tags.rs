#![feature(plugin)]
#![feature(nll)]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate crossbeam;
extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_sts;
extern crate serde_json;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;

use crossbeam::scope;
use rusoto_core::{AutoRefreshingProvider, Region};
use rusoto_ec2::{
    CreateTagsRequest, DescribeTagsRequest, Ec2, Ec2Client, Filter, Tag, TagDescription,
};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use serde_json::Value;
use slog::Drain;
use std::{env, error::Error, fs::read_to_string, process::exit, str::FromStr};

fn main() -> Result<(), Box<Error>> {
    let args: Vec<_> = env::args().collect();
    if args.is_empty() {
        println!(
            "usage: copy-ami-tags-rs <role_name> <source_account> <shared_account,shared_account>"
        );
        exit(1);
    }

    let role_name = &args[1];
    let source_account = &args[2];
    let shared_account: &Vec<&str> = &args[3].split(',').collect();

    // attempt to deserialize the config to our struct
    let manifest: Value = match serde_json::from_str(&read_to_string(&"manifest.json")?) {
        Ok(json) => json,
        Err(_) => {
            logging("crit", "manifest.json not valid json?").is_ok();
            exit(1)
        }
    };

    // grab the list of artifacts
    let artifacts = match manifest["builds"][0]["artifact_id"].as_str() {
        Some(artifacts) => artifacts,
        _ => {
            logging("crit", "No artifacts present in manifest").is_ok();
            exit(1)
        }
    };

    // loop through each region:ami pair
    scope(|scope| {
        for artifact in artifacts.split(',') {
            let pair: Vec<&str> = artifact.split(':').collect();
            logging(
                "info",
                &format!(
                    "Processing {} within region {} for ami {}",
                    &source_account, &pair[0], &pair[1]
                ),
            ).is_ok();
            scope.spawn(move || {
                source_ami(role_name, source_account, shared_account, pair[0], pair[1]).is_ok();
            });
        }
    });
    Ok(())
}

fn source_ami(
    role: &str,
    source_account: &str,
    shared_account: &[&str],
    region: &str,
    ami: &str,
) -> Result<(), Box<Error>> {
    // create our role_name from the source account and provided role name
    let role_name = format!("arn:aws:iam::{}:role/{}", source_account, role);

    // set up our credentials provider for aws
    let sts_client = StsClient::simple(Region::from_str(region)?);

    // generate a sts provider
    let sts_provider = StsAssumeRoleSessionCredentialsProvider::new(
        sts_client,
        role_name.to_owned(),
        "packer-api".to_owned(),
        None,
        None,
        None,
        None,
    );

    // allow our STS to auto-refresh
    let _auto_sts_provider = match AutoRefreshingProvider::with_refcell(sts_provider) {
        Ok(auto_sts_provider) => auto_sts_provider,
        Err(_) => {
            logging("crit", "Unable to load STS credentials").is_ok();
            exit(1)
        }
    };

    // create our ec2 client initialization
    let client = Ec2Client::simple(Region::from_str(region)?);

    // create our filter for the source ami
    let filter = Filter {
        name: Some("resource-id".to_string()),
        values: Some(vec![ami.to_owned()]),
    };

    // create our request
    let tags_request = DescribeTagsRequest {
        filters: Some(vec![filter]),
        ..Default::default()
    };

    logging(
        "info",
        &format!(
            "Requesting tags in {} within region {} for ami {}",
            &source_account, &region, &ami
        ),
    ).is_ok();

    // grab those tags and attempt to unwrap them
    // if successful, then send those tags to the dest ami
    match client.describe_tags(&tags_request).sync() {
        Ok(_src_ami) => {
            destination_ami(region, ami, shared_account, role, &_src_ami.tags.unwrap()).is_ok();
        }
        Err(e) => {
            logging(
                "crit",
                &format!("Unable to collect tags for {} Error: {:?}", ami, e),
            ).is_ok();
            exit(1)
        }
    };
    Ok(())
}

fn destination_ami(
    region: &str,
    ami: &str,
    shared_account: &[&str],
    role: &str,
    source_ami_tags: &[TagDescription],
) -> Result<(), Box<Error>> {
    scope(|scope| {
        for account in shared_account {
            let source_ami_tags: Vec<_> = source_ami_tags.to_owned();
            scope.spawn(move || {
                //        logging(&format!("Applying tags -- ACCOUNT: {} REGION: {} AMI: {}", &account, &region, &ami));
                // create our role_name from account and provided name
                let role_name = format!("arn:aws:iam::{}:role/{}", account, role);

                // initiate our sts client
                let sts_client = StsClient::simple(Region::from_str(region).unwrap());

                // generate a sts provider
                let sts_provider = StsAssumeRoleSessionCredentialsProvider::new(
                    sts_client,
                    role_name.to_owned(),
                    "packer-api".to_owned(),
                    None,
                    None,
                    None,
                    None,
                );

                // allow our STS to auto-refresh
                let _auto_sts_provider =
                    AutoRefreshingProvider::with_refcell(sts_provider).unwrap();

                // create our ec2 client initialization
                let client = Ec2Client::simple(Region::from_str(region).unwrap());

                // create mutable vec of our source ami tags
                let mut tags: Vec<_> = vec![];

                // loop through the tags from our source ami and add it to our mutable tags_buff vec
                for tag in source_ami_tags {
                    tags.push(Tag {
                        key: Some(tag.key.unwrap().to_string()),
                        value: Some(tag.value.unwrap().to_string()),
                    })
                }

                // create a CreateTagsRequest
                let tag_request = CreateTagsRequest {
                    resources: vec![ami.to_owned()],
                    tags,
                    ..Default::default()
                };

                // apply tags
                if client.create_tags(&tag_request).sync().is_ok() {
                    logging(
                        "info",
                        &format!(
                            "Copied tags to {} within region {} for ami {}",
                            account, region, ami
                        ),
                    ).is_ok()
                } else {
                    logging(
                        "error",
                        &format!(
                            "Unsuccessful in copying tags to {} within region {} for ami {} ",
                            account, region, ami
                        ),
                    ).is_ok()
                };
            });
        }
    });
    Ok(())
}

fn logging(log_type: &str, msg: &str) -> Result<(), Box<Error>> {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, o!());

    match log_type {
        "info" => {
            info!(logger, "copy-ami-tags"; "[*]" => &msg);
            Ok(())
        }
        "error" => {
            error!(logger, "copy-ami-tags"; "[*]" => &msg);
            Ok(())
        }
        "crit" => {
            crit!(logger, "copy-ami-tags"; "[*]" => &msg);
            Ok(())
        }
        _ => Ok(()),
    }
}
