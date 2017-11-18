#![feature(plugin)]
#![cfg_attr(feature = "clippy", plugin(clippy))]

extern crate rusoto_core;
extern crate rusoto_ec2;
extern crate rusoto_sts;
extern crate crossbeam;
extern crate serde_json;
use std::env;
use std::str::FromStr;
use std::fs::File;
use rusoto_core::{default_tls_client, AutoRefreshingProvider, DefaultCredentialsProvider, Region};
use rusoto_sts::{StsAssumeRoleSessionCredentialsProvider, StsClient};
use rusoto_ec2::{Ec2Client, Ec2, TagDescription, DescribeTagsRequest, CreateTagsRequest, Tag, Filter};
use crossbeam::scope;
use serde_json::Value;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("usage: copy-ami-tags-rs <role_name> <source_account> <shared_account,shared_account>");
    }

    let role_name = &args[1];
    let source_account = &args[2];
    let shared_account: &Vec<&str> = &args[3].split(',').collect();

    // open our config file
    let packer_manifest = File::open(&"manifest.json").expect("could not open file");
    // attempt to deserialize the config to our struct
    let manifest: Value = serde_json::from_reader(packer_manifest).expect("config has invalid json");
    // grab the list of artifacts
    let artifacts = manifest["builds"][0]["artifact_id"].as_str().unwrap();

    // loop through each region:ami pair
    for artifact in artifacts.split(',') {
        let pair: Vec<&str> = artifact.split(':').collect();
        scope(|scope| {
            scope.spawn(move || {
                println!("[*] Processing AMI {} in REGION {} for ACCOUNT {}", &pair[0], &pair[1], &source_account);
                source_ami(role_name, source_account, shared_account, pair[0], pair[1] );
            });
        });
    }
}

fn source_ami(role: &str, source_account: &str, shared_account: &[&str], region: &str, ami: &str,) {
    scope(|scope| {
        scope.spawn(move || {
            // create our role_name from the source account and provided role name
            let role_name = format!("arn:aws:iam::{}:role/{}", source_account, role);

            // set up our credentials provider for aws
            let provider = match DefaultCredentialsProvider::new() {
                Ok(provider) => provider,
                Err(err) => panic!("Unable to load credentials. {}", err)
            };

            // initiate our sts client
            let sts_client = StsClient::new(
                default_tls_client().unwrap(),
                provider,
                Region::from_str(region).unwrap()
            );

            // generate a sts provider
            let sts_provider = StsAssumeRoleSessionCredentialsProvider::new(
                sts_client,
                role_name.to_owned(),
                "packer-api".to_owned(),
                None,
                None,
                None,
                None
            );
            // allow our STS to auto-refresh
            let auto_sts_provider = AutoRefreshingProvider::with_refcell(sts_provider).unwrap();

            // create our ec2 client initialization
            let client = Ec2Client::new(
                default_tls_client().unwrap(),
                auto_sts_provider,
                Region::from_str(region).unwrap()
            );

            // create our filter for the source ami
            let filter = Filter { name: Some("resource-id".to_string()), values: Some(vec![ami.to_owned()]) };

            // create our request
            let tags_request = DescribeTagsRequest { filters: Some(vec![filter]), ..Default::default() };

            println!("[*] Requesting tags from AMI {} in REGION {} for ACCOUNT {}", &ami, &region, &source_account);

            // grab those tags and attempt to unwrap them
            // if successful, then send those tags to the dest ami
            match client.describe_tags(&tags_request) {
                Ok(_src_ami) => destination_ami(region, ami, shared_account, role, &_src_ami.tags.unwrap()),
                Err(e) => eprintln!("Unable to collect tags\n\tError: {:?}", e)
            };
        });
    });
}

fn destination_ami(region: &str, ami: &str, shared_account: &[&str], role: &str, source_ami_tags: &[TagDescription]) {

    for account in shared_account {
        let source_ami_tags: Vec<_> = source_ami_tags.to_owned();
        scope(|scope| {
            scope.spawn(move || {

                println!("[*] Applying tags to AMI {} in REGION {} for ACCOUNT {}", &ami, &region, &account);
                // create our role_name from account and provided name
                let role_name = format!("arn:aws:iam::{}:role/{}", account, role);

                // set up our credentials provider for aws
                let provider = match DefaultCredentialsProvider::new() {
                    Ok(provider) => provider,
                    Err(err) => panic!("Unable to load credentials. {}", err)
                };

                // initiate our sts client
                let sts_client = StsClient::new(
                    default_tls_client().unwrap(),
                    provider,
                    Region::from_str(region).unwrap()
                );

                // generate a sts provider
                let sts_provider = StsAssumeRoleSessionCredentialsProvider::new(
                    sts_client,
                    role_name.to_owned(),
                    "packer-api".to_owned(),
                    None,
                    None,
                    None,
                    None
                );
                // allow our STS to auto-refresh
                let auto_sts_provider = AutoRefreshingProvider::with_refcell(sts_provider).unwrap();

                // create our ec2 client initialization
                let client = Ec2Client::new(
                    default_tls_client().unwrap(),
                    auto_sts_provider,
                    Region::from_str(region).unwrap()
                );

                // create mutable vec of our source ami tags
                let mut tags_buff: Vec<_> = vec![];

                // loop through the tags from our source ami and add it to our mutable tags_buff vec
                for tag in source_ami_tags {
                    tags_buff.push( Tag { key: Some(tag.key.unwrap().to_string()), value: Some(tag.value.unwrap().to_string())  } )
                }

                // create a CreateTagsRequest
                let tag_request = CreateTagsRequest { resources: vec![ami.to_owned()], tags: tags_buff, ..Default::default() };

                // apply tags
                match client.create_tags(&tag_request) {
                    Ok(_) => println!("[*] Successfully copied tags to AMI {} in ACCOUNT {} for REGION {}", ami, account, region ),
                    Err(e) => eprintln!("[*] Unsuccessful in copying tags from AMI {} to ACCOUNT {} for REGION {}\n\t{:?}", ami, account, region, e)
                }
            });
        });
    }
}
