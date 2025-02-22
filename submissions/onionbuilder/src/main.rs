use std::path::PathBuf;
use structopt::StructOpt;
use onionbuilder::{OnionPayload, SphinxCrypto, OnionPacketBuilder, Error};

#[derive(StructOpt, Debug)]
#[structopt(
    name = "onionbuilder",
    about = "A tool for creating onion routing packets",
)]
struct Opt {
    /// Output directory for the generated packet
    #[structopt(parse(from_os_str))]
    output_dir: PathBuf,

    /// Input JSON file containing the routing information
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn run(opt: Opt) -> Result<(), Error> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&opt.output_dir)?;

    // Load and parse the input file
    let onion_payload = OnionPayload::from_json_file(&opt.input)?;

    // Initialize cryptographic operations
    let mut crypto = SphinxCrypto::new(onion_payload)?;
    
    // Generate keys and secrets for each hop
    crypto.generate_hop_keys_secrets()?;

    // Create the packet builder and construct the final packet
    let mut builder = OnionPacketBuilder::new(crypto.onion_payload);
    let final_packet = builder.construct_packet()?;

    // Create the output file path
    let output_path = opt.output_dir.join("output.txt");

    // Write the final packet to the output file in hex format
    std::fs::write(&output_path, hex::encode(final_packet))?;

    Ok(())
}

fn main() {
    let opt = Opt::from_args();

    if let Err(err) = run(opt) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}