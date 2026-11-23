import sys
import csv
import re
from bolt11 import decode
from dataclasses import dataclass
from typing import Any

@dataclass
class RouteHop:
    path_id: int
    channel_name: str
    cltv_delta: int
    base_fee_msat: int
    proportional_fee_ppm: int

@dataclass
class Path:
    """Represents a single path in a multipart payment"""
    hops: list[RouteHop]
    amount_msat: int  # Amount allocated to this path

@dataclass
class MultiPartRoute:
    """Represents a complete multipart payment route"""
    paths: list[Path]
    
    def validate_amounts(self, total_amount_msat: int) -> bool:
        """Verify that path amounts sum to total payment amount"""
        return sum(path.amount_msat for path in self.paths) == total_amount_msat

@dataclass
class InvoiceInfo:
    amount_msat: int
    min_final_cltv_expiry: int

def group_hops_into_paths(hops: list[RouteHop]) -> list[Path]:
    """Group hops by path_id into separate Path objects, maintaining input order"""
    paths_dict = {}
    current_path_id = None
    current_path_hops = []
    
    for hop in hops:
        if current_path_id != hop.path_id:
            # If we have collected hops for a path, save them
            if current_path_hops:
                paths_dict[current_path_id] = Path(hops=current_path_hops, amount_msat=0)
            # Start new path
            current_path_id = hop.path_id
            current_path_hops = []
        current_path_hops.append(hop)
    
    if current_path_hops:
        paths_dict[current_path_id] = Path(hops=current_path_hops, amount_msat=0)
    
    # Return paths in order of their first appearance
    return list(paths_dict.values())

def allocate_amounts_to_paths(paths: list[Path], total_amount_msat: int) -> None:
    """Allocate the total amount across paths"""
    base_amount = total_amount_msat // len(paths)
    
    for i, path in enumerate(paths):
        path.amount_msat = base_amount

def parse_hops(input_file_path: str) -> list[RouteHop]:
    """Parse hops in route."""
    try:
        with open(input_file_path) as f:
            reader = csv.DictReader(f)
            hops = [RouteHop(
                path_id=int(row['path_id']),
                channel_name=row['channel_name'],
                cltv_delta=int(row['cltv_delta']),
                base_fee_msat=int(row['base_fee_msat']),
                proportional_fee_ppm=int(row['proportional_fee_ppm'])
            ) for row in reader]
        return hops
    except (FileNotFoundError, KeyError, ValueError) as e:
        raise ValueError(f"Error reading input file: {e}")


def parse_invoice(invoice: str) -> InvoiceInfo:
    """Parse both amount and min_final_cltv_expiry from a Lightning Network invoice."""
    # Extract the amount part from the invoice
    # Format is: lnbcrt[amount][multiplier]
    try:
        # Decode the complete invoice using bolt11 library
        decoded = decode(invoice)
        
        # Extract the amount, ensuring it exists
        if decoded.amount_msat is None:
            raise ValueError("Invoice does not specify an amount")
        
        return InvoiceInfo(
            amount_msat=decoded.amount_msat,
            min_final_cltv_expiry=decoded.min_final_cltv_expiry
        )
        
    except Exception as e:
        raise ValueError(f"Failed to parse invoice: {str(e)}")

def calculate_fees(amount_msat: int, hop: RouteHop) -> int:
    """Calculate fees for a hop based on base fee and proportional fee."""
    proportional_fee = (amount_msat * hop.proportional_fee_ppm) // 1_000_000
    return hop.base_fee_msat + proportional_fee

def compute_htlc_amounts(hops: list[RouteHop], invoice_amount: int) -> list[int]:
    """Calculate HTLC amounts backward (from destination to source)"""
    htlc_amounts = [invoice_amount]  # Start with final amount
    for hop in list(reversed(hops))[:-1]:  # Skip last hop when calculating fees
        next_amount = htlc_amounts[-1]
        amount_with_fees = next_amount + calculate_fees(next_amount, hop)
        htlc_amounts.append(amount_with_fees)
    return htlc_amounts[::-1]

def compute_htlc_expiry(hops: list[RouteHop], current_block_height: int, min_final_cltv_expiry_delta: int) -> list[int]:
    """Calculate HTLC expiry backward (from destination to source)"""
    expiry = min_final_cltv_expiry_delta+current_block_height
    htlc_expiries = [expiry]
    reversed_hops = list(reversed(hops))[:-1]
    for hop in reversed_hops:
        expiry += hop.cltv_delta
        htlc_expiries.append(expiry)
    # convert it back 
    return htlc_expiries[::-1]

def prepare_output_data(hops: RouteHop, htlc_amounts: list[int], htlc_expiries: list[int]) -> list[Any]:
    """Construct output data"""
    output_data = []
    for i, hop in enumerate(hops):
        output_data.append([
            hop.path_id,
            hop.channel_name,
            htlc_amounts[i],
            htlc_expiries[i],
            'NULL'
        ])
    return output_data

def process_multipart_route(
    input_file_path: str,
    output_file_path: str,
    payment_request_hex: str,
    current_block_height: int
) -> None:
    # Parse invoice info
    invoice_info = parse_invoice(payment_request_hex)
    
    # Parse all hops
    hops = parse_hops(input_file_path)
    
    # Group hops into paths
    paths = group_hops_into_paths(hops)
    
    # Allocate amounts to paths
    allocate_amounts_to_paths(paths, invoice_info.amount_msat)
    
    # Create MultiPartRoute and validate
    route = MultiPartRoute(paths=paths)
    if not route.validate_amounts(invoice_info.amount_msat):
        raise ValueError("Path amounts don't sum to total payment amount")
    
    # Process each path
    all_output_data = []
    for path in route.paths:
        # Calculate HTLC amounts for this path
        htlc_amounts = compute_htlc_amounts(path.hops, path.amount_msat)
        
        # Calculate HTLC expiry for this path
        htlc_expiries = compute_htlc_expiry(
            path.hops, 
            current_block_height,
            invoice_info.min_final_cltv_expiry
        )
        
        # Prepare output data for this path
        path_output = prepare_output_data(path.hops, htlc_amounts, htlc_expiries)
        all_output_data.extend(path_output)
    
    # Write all paths to output file
    with open(output_file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(all_output_data)


if __name__ == '__main__':
    output_path = sys.argv[1] + "/output.csv"
    input_path = sys.argv[2]
    payment_request_hex = sys.argv[3]
    current_block_height = int(sys.argv[4])

    try:
        process_multipart_route(input_path, output_path, payment_request_hex, current_block_height)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
