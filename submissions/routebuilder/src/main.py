import sys
import csv

output_file_path = sys.argv[1]
input_file_path = sys.argv[2]
payment_request_hex = sys.argv[3]
current_block_height = int(sys.argv[4])

input_data = []

with open(input_file_path) as f:
    input_data = list(csv.DictReader(f))


output_data = []

for row in input_data:
    output_data.append({
        'path_id': row['path_id'],
        'channel_name': row['channel_name'],
        'amount': row['base_fee_msat'],
        'expiry': row['cltv_delta'],
        'NULL': 'NULL'
    })

with open(output_file_path + "/output.csv", 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['path_id', 'channel_name', 'amount', 'expiry', 'NULL'])
    writer.writerows(output_data)
