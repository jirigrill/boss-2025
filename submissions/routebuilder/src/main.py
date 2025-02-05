import sys
import csv
import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RouteHop:
    path_id: int
    channel_name: str
    cltv_delta: int
    base_fee_msat: int
    proportional_fee_ppm: int


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


def parse_amount(invoice: str) -> int:
    """
    Parse the amount from a invoice.
    Returns amount in millisatoshis.
    """
    # Extract the amount part from the invoice
    # Format is: lnbcrt[amount][multiplier]
    match = re.match(r'lnbcrt(\d+)([munp])?1', invoice.lower())
    if not match:
        raise ValueError("Invalid invoice format")
    
    amount, multiplier = match.groups()
    amount = int(amount)
    
    # Convert to millisatoshis based on multiplier
    multipliers = {
        'm': 100_000_000,  # milli (100,000,000 msats = 1 mBTC)
        'u': 100,          # micro
        'n': 0.1,         # nano
        'p': 0.0001,      # pico
        None: 100_000_000_000  # no multiplier means BTC
    }
    return int(amount * multipliers[multiplier])


def calculate_fees(amount_msat: int, hop: RouteHop) -> int:
    """Calculate fees for a hop based on base fee and proportional fee."""
    proportional_fee = (amount_msat * hop.proportional_fee_ppm) // 1_000_000
    return hop.base_fee_msat + proportional_fee


def compute_htlc_amounts(hops: list[RouteHop], invoice_amount: int) -> list[int]:
    """Calculate HTLC amounts backward (from destination to source)"""
    htlc_amounts = [invoice_amount]  # Start with final amount
    for hop in reversed(hops[:-1]):  # Skip last hop when calculating fees
        next_amount = htlc_amounts[-1]
        amount_with_fees = next_amount + calculate_fees(next_amount, hop)
        htlc_amounts.append(amount_with_fees)
    return htlc_amounts[::-1]  # Reverse to match forward route order


def compute_htlc_expiry(hops: list[RouteHop], current_block_height: int) -> list[int]:
    """Calculate HTLC expiry forward (from source to destination)"""
    expiry = current_block_height
    htlc_expiries = []
    for hop in hops:
        expiry += hop.cltv_delta
        htlc_expiries.append(expiry)
    return htlc_expiries


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


def process_route(
    input_file_path: str,
    output_file_path: str,
    payment_request_hex: str,
    current_block_height: int
) -> None:
     # Parse the payment amount from BOLT11 invoice
    try:
        payment_amount_msat = parse_amount(payment_request_hex)
    except ValueError as e:
        raise ValueError(f"Error parsing payment request: {e}")

    # Parse hops in route
    try:
        hops = parse_hops(input_file_path)
    except (FileNotFoundError, KeyError, ValueError) as e:
        raise ValueError(f"Error reading input file: {e}")

    # Calculate HTLC amounts
    htlc_amounts = compute_htlc_amounts(hops, payment_amount_msat)

    # Calculate HTLC expiry 
    htlc_expiries = compute_htlc_expiry(hops, current_block_height)

    # Prepare output data
    output_data = prepare_output_data(hops, htlc_amounts, htlc_expiries)

    # Write output file
    try:
        with open(output_file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(output_data)
    except IOError as e:
        raise ValueError(f"Error writing output file: {e}")


if __name__ == '__main__':
    output_path = sys.argv[1] + "/output.csv"
    input_path = sys.argv[2]
    payment_request_hex = sys.argv[3]
    current_block_height = int(sys.argv[4])

    try:
        process_route(input_path, output_path, payment_request_hex, current_block_height)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
