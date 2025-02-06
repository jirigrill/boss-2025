use std::path::PathBuf;
use std::error::Error;
use std::fs::File;
use serde::{Deserialize, Serialize};
use clap::Parser;
use lightning_invoice::Bolt11Invoice;


// Command line argument structure using clap
#[derive(Parser, Debug)]
#[command(author, version, about = "Process payment routes")]
struct Args {
    #[arg(value_name = "OUTPUT_DIR")]
    output_dir: PathBuf,

    #[arg(value_name = "INPUT_FILE")]
    input_file: PathBuf,

    #[arg(value_name = "PAYMENT_REQUEST")]
    payment_request_hex: String,

    #[arg(value_name = "BLOCK_HEIGHT")]
    current_block_height: u32,
}

// Equivalent to Python's RouteHop dataclass
#[derive(Debug, Deserialize)]
struct RouteHop {
    path_id: u32,
    channel_name: String,
    cltv_delta: u32,
    base_fee_msat: u64,
    proportional_fee_ppm: u32,
}

#[derive(Debug, Serialize)]
struct OutputRecord {
    path_id: u32,
    channel_name: String,
    htlc_amount_msat: u64,
    htlc_expiry: u32,
    tlv: String,
}

struct InvoiceInfo {
    amount_msat: u64,
    min_final_cltv_expiry: u32,
}

fn parse_invoice(invoice_str: &str) -> Result<InvoiceInfo, Box<dyn Error>> {
    // Parse the invoice string into a Bolt11Invoice
    let invoice: Bolt11Invoice = invoice_str.parse()
        .map_err(|e| format!("Failed to parse invoice: {}", e))?;
    
    // Extract amount in millisatoshis
    let amount_msat = invoice.amount_milli_satoshis()
        .ok_or("Invoice does not specify an amount")?;
    
    // Get min_final_cltv_expiry (defaults to 18 as per BOLT-11 spec)
    let min_final_cltv_expiry = invoice.min_final_cltv_expiry_delta().try_into().unwrap();
    
    Ok(InvoiceInfo {
        amount_msat,
        min_final_cltv_expiry,
    })
}

fn calculate_fees(amount_msat: u64, hop: &RouteHop) -> u64 {
    let proportional_fee = (amount_msat * hop.proportional_fee_ppm as u64) / 1_000_000;
    hop.base_fee_msat + proportional_fee
}

fn compute_htlc_amounts(hops: &[RouteHop], invoice_amount: u64) -> Vec<u64> {
    let mut amounts = vec![invoice_amount];
    for hop in hops.iter().rev().skip(1) {
        let next_amount = *amounts.last().unwrap();
        let amount_with_fees = next_amount + calculate_fees(next_amount, hop);
        amounts.push(amount_with_fees);
    }
    amounts.into_iter().rev().collect()
}

fn compute_htlc_expiry(
    hops: &[RouteHop], 
    current_block_height: u32,
    min_final_cltv_expiry_delta: u32
) -> Vec<u32> {
    // Start with final expiry (matching Python behavior)
    let mut expiry = current_block_height + min_final_cltv_expiry_delta;
    let mut expiries = vec![expiry];
    
    // Calculate expiries backwards, skipping last hop
    for hop in hops.iter().rev().skip(1) {
        expiry += hop.cltv_delta;
        expiries.push(expiry);
    }
    
    expiries.into_iter().rev().collect()
}

fn process_route(args: &Args) -> Result<(), Box<dyn Error>> {
    // Parse payment amount
    let invoice_info = parse_invoice(&args.payment_request_hex)?;
    
    // Read and parse input CSV
    let input_file = File::open(&args.input_file)?;
    let mut reader = csv::Reader::from_reader(input_file);
    let hops: Vec<RouteHop> = reader.deserialize().collect::<Result<_, _>>()?;
    
    // Calculate HTLC amounts and expiries
    let htlc_amounts = compute_htlc_amounts(&hops, invoice_info.amount_msat);
    let htlc_expiries = compute_htlc_expiry(&hops, args.current_block_height, invoice_info.min_final_cltv_expiry);
    
    // Prepare and write output
    let output_path = args.output_dir.join("output.csv");
    let output_file = File::create(output_path)?;
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(output_file);
    
    for ((hop, amount), expiry) in hops.iter().zip(htlc_amounts).zip(htlc_expiries) {
        let record = OutputRecord {
            path_id: hop.path_id,
            channel_name: hop.channel_name.clone(),
            htlc_amount_msat: amount,
            htlc_expiry: expiry,
            tlv: String::from("NULL"),
        };
        writer.serialize(record)?;
    }
    
    writer.flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    process_route(&args)?;
    Ok(())
}