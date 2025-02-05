use std::path::PathBuf;
use std::error::Error;
use std::fs::File;
use serde::{Deserialize, Serialize};
use clap::Parser;

// Command line argument structure using clap
#[derive(Parser, Debug)]
#[command(author, version, about = "Process CSV files for payment routing")]
struct Args {
    /// Directory where the output CSV will be written
    #[arg(value_name = "OUTPUT_DIR")]
    output_dir: PathBuf,

    /// Input CSV file containing the payment route data
    #[arg(value_name = "INPUT_FILE")]
    input_file: PathBuf,

    /// Hex-encoded payment request string
    #[arg(value_name = "PAYMENT_REQUEST")]
    payment_request_hex: String,

    /// Current blockchain height
    #[arg(value_name = "BLOCK_HEIGHT")]
    current_block_height: u32,
}

// Input CSV record structure
#[derive(Debug, Deserialize)]
struct InputRecord {
    path_id: String,
    channel_name: String,
    base_fee_msat: String,
    cltv_delta: String,
}

// Output CSV record structure
#[derive(Debug, Serialize)]
struct OutputRecord {
    path_id: u32,          // Hardcoded to 0
    channel_name: String,
    htlc_amount_msat: u64, // Converted from base_fee_msat
    htlc_expiry: u32,      // Converted from cltv_delta
    tlv: String,           // Hardcoded to "NULL"
}

// Function to process CSV data
fn process_csv(args: &Args) -> Result<(), Box<dyn Error>> {
    // Create CSV reader
    let input_file = File::open(&args.input_file)?;
    let mut reader = csv::Reader::from_reader(input_file);

    // Create output file
    let output_path = args.output_dir.join("output.csv");
    let output_file = File::create(output_path)?;
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false) 
        .from_writer(output_file);

    // Process records
    for result in reader.deserialize() {
        let record: InputRecord = result?;
        
        let output_record = OutputRecord {
            path_id: 0, // Hardcoded as specified
            channel_name: record.channel_name,
            htlc_amount_msat: record.base_fee_msat.parse()?,
            htlc_expiry: record.cltv_delta.parse()?,
            tlv: String::from("NULL"),
        };

        writer.serialize(output_record)?;
    }

    writer.flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parse command line arguments using clap
    let args = Args::parse();

    // Process the CSV file
    process_csv(&args)?;

    Ok(())
}
