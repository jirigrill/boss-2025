# Which public key signed input 0 in this tx:
#   `e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163`
TRANSACTION="e5969add849689854ac7f28e45628b89f7454b83e9699e551ce14b6f90c86163"

TRANSACTION_DETAIL=$(bitcoin-cli getrawtransaction "$TRANSACTION" true)
INPUT_WITNESS=$(echo "$TRANSACTION_DETAIL" | jq -r '.vin.[].txinwitness')
SCRIPT=$(echo "$INPUT_WITNESS" | jq -r '.[2]')
DECODED_SCRIPT=$(bitcoin-cli decodescript "$SCRIPT")
PUBKEY=$(echo "$DECODED_SCRIPT" | jq -r '.asm' | awk '{print $2}')

echo $PUBKEY

