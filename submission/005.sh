BITCOIN_CLI="/Users/jirigrill/Developer/boss-2025/bitcoin-28.0/bin/bitcoin-cli -rpcconnect=boss2025.xyz -rpcuser=user_109 -rpcpassword=yDmnDngYdM1V"

# Create a 1-of-4 P2SH multisig address from the public keys in the four inputs of this tx:
#   `37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517`

TRANSACTION="37d966a263350fe747f1c606b159987545844a493dd38d84b070027a895c4517"

WITNESS_DATA=$($BITCOIN_CLI getrawtransaction "$TRANSACTION" true | jq -r '.vin[].txinwitness[1] // "null"')

JSON_ARRAY="["
first=true
while IFS= read -r line; do
    if [ "$line" != "null" ]; then
        if [ "$first" = true ]; then
            JSON_ARRAY+="\"$line\""
            first=false
        else
            JSON_ARRAY+=", \"$line\""
        fi
    fi
done <<< "$WITNESS_DATA"
JSON_ARRAY+="]"

# Execute createmultisig command
$BITCOIN_CLI createmultisig 1 "$JSON_ARRAY" | jq -r '.address'