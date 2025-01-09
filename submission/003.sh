# How many new outputs were created by block 123,456?
BLOCK_NUM=123456

# Get the block hash first (we can see this works from your terminal test)
HASH=$(bitcoin-cli getblockhash "$BLOCK_NUM" 2>/dev/null)
if [ -z "$HASH" ]; then
    echo "Failed to get block hash"
    exit 1
fi

echo "$(bitcoin-cli getblock "$HASH" 2 2>/dev/null | \
    jq -r '.tx | map(.vout | length) | add')"