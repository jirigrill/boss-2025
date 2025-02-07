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

#[derive(Debug, Deserialize)]
struct RouteHop {
    path_id: u32,
    channel_name: String,
    cltv_delta: u32,
    base_fee_msat: u64,
    proportional_fee_ppm: u32,
}

// Represents a single path in a multipart payment
#[derive(Debug)]
struct Path {
    /// The sequence of hops that make up this path
    hops: Vec<RouteHop>,
    /// Amount allocated to this path in millisatoshis
    amount_msat: u64,
}

// Represents a complete multipart payment route
#[derive(Debug)]
struct MultiPartRoute {
    // Collection of paths that make up the multipart payment
    paths: Vec<Path>,
}

impl MultiPartRoute {
    // Verify that path amounts sum to total payment amount
    fn validate_amounts(&self, total_amount_msat: u64) -> bool {
        self.paths.iter().map(|p| p.amount_msat).sum::<u64>() == total_amount_msat
    }
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
fn group_hops_into_paths(hops: Vec<RouteHop>) -> Vec<Path> {
    // Group hops by path_id into separate Path objects, maintaining input order
    let mut paths: Vec<Path> = Vec::new();
    let mut current_path_id = None;
    let mut current_path_hops = Vec::new();

    for hop in hops {
        if current_path_id != Some(hop.path_id) {
            // If we have collected hops for a path, save them
            if !current_path_hops.is_empty() {
                paths.push(Path {
                    hops: current_path_hops,
                    amount_msat: 0,
                });
                current_path_hops = Vec::new();
            }
            // Start new path
            current_path_id = Some(hop.path_id);
        }
        current_path_hops.push(hop);
    }

    // Handle the last path if it exists
    if !current_path_hops.is_empty() {
        paths.push(Path {
            hops: current_path_hops,
            amount_msat: 0,
        });
    }

    paths
}

fn allocate_amounts_to_paths(paths: &mut Vec<Path>, total_amount_msat: u64) {
    // Allocate the total amount across paths evenly

    // Calculate base amount for each path
    let base_amount = total_amount_msat / paths.len() as u64;
    
    // Assign base amount to each path
    for path in paths.iter_mut() {
        path.amount_msat = base_amount;
    }
}

fn calculate_fees(amount_msat: u64, hop: &RouteHop) -> u64 {
    let proportional_fee = (amount_msat * hop.proportional_fee_ppm as u64) / 1_000_000;
    hop.base_fee_msat + proportional_fee
}

fn compute_htlc_amounts(hops: &[RouteHop], invoice_amount: u64) -> Vec<u64> {
    let mut amounts = vec![invoice_amount];  // Start with final amount
    
    // First reverse all hops, then take all but the last one
    let reversed_hops: Vec<_> = hops.iter().rev().collect();
    let hops_to_process = &reversed_hops[..reversed_hops.len()-1];
    
    for hop in hops_to_process {
        let next_amount = *amounts.last().unwrap();
        let amount_with_fees = next_amount + calculate_fees(next_amount, hop);
        amounts.push(amount_with_fees);
    }
    
    amounts.into_iter().rev().collect()  // Reverse to match forward route order
}

fn compute_htlc_expiry(
    hops: &[RouteHop], 
    current_block_height: u32,
    min_final_cltv_expiry_delta: u32
) -> Vec<u32> {
    // Start with final expiry
    let mut expiry = current_block_height + min_final_cltv_expiry_delta;
    let mut expiries = vec![expiry];
    
    // Process hops in reverse order, excluding the final hop
    let reversed_hops: Vec<_> = hops.iter().rev().collect();
    for hop in reversed_hops.iter().take(hops.len() - 1) {
        expiry += hop.cltv_delta;
        expiries.push(expiry);
    }
    
    // Reverse again to get forward path order
    expiries.into_iter().rev().collect()
}

fn process_multipart_route(args: &Args) -> Result<(), Box<dyn Error>> {
    // Process a multipart payment route, computing HTLC amounts and expiries for each path
    
    // Parse invoice info from the payment request
    let invoice_info = parse_invoice(&args.payment_request_hex)?;
    
     // Read the input file content
     let file_content = std::fs::read_to_string(&args.input_file)?;
    
     // Print the file content to console
     println!("Input file contents:");
     println!("{}", file_content);
     
     // Create CSV reader from the content string
     let mut reader = csv::ReaderBuilder::new()
         .from_reader(file_content.as_bytes());
     let hops: Vec<RouteHop> = reader.deserialize().collect::<Result<_, _>>()?;
    
    // Group hops into distinct paths and allocate payment amounts
    let mut paths = group_hops_into_paths(hops);
    allocate_amounts_to_paths(&mut paths, invoice_info.amount_msat);
    
    // Create MultiPartRoute and validate total amounts
    let route = MultiPartRoute { paths };
    if !route.validate_amounts(invoice_info.amount_msat) {
        return Err("Path amounts don't sum to total payment amount".into());
    }

    // Set up CSV writer for output file
    let output_path = args.output_dir.join("output.csv");
    let output_file = File::create(output_path)?;
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(output_file);

    // Process each path in the route
    for path in route.paths.iter() {
        // Calculate HTLC amounts and expiries for this path
        let htlc_amounts = compute_htlc_amounts(&path.hops, path.amount_msat);
        let htlc_expiries = compute_htlc_expiry(
            &path.hops,
            args.current_block_height,
            invoice_info.min_final_cltv_expiry
        );

        // Write records for each hop in the path
        for ((hop, amount), expiry) in path.hops.iter().zip(htlc_amounts).zip(htlc_expiries) {
            let record = OutputRecord {
                path_id: hop.path_id,
                channel_name: hop.channel_name.clone(),
                htlc_amount_msat: amount,
                htlc_expiry: expiry,
                tlv: String::from("NULL"),
            };
            writer.serialize(record)?;
        }
    }
    
    // Ensure all data is written to file
    writer.flush()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    process_multipart_route(&args)?;
    Ok(())
}