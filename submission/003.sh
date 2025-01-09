# How many new outputs were created by block 123,456?
BITCOIN_CLI="/Users/jirigrill/Developer/boss-2025/bitcoin-28.0/bin/bitcoin-cli -rpcconnect=boss2025.xyz -rpcuser=user_109 -rpcpassword=yDmnDngYdM1V"

BLOCK_NUM=123456

# Get the block hash first (we can see this works from your terminal test)
HASH=$($BITCOIN_CLI getblockhash "$BLOCK_NUM" 2>/dev/null)
if [ -z "$HASH" ]; then
    echo "Failed to get block hash"
    exit 1
fi

echo "$($BITCOIN_CLI getblock "$HASH" 2 2>/dev/null | \
    jq -r '.tx | map(.vout | length) | add')"