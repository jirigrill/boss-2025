#!/bin/bash
# Fill in lncli commands to lookup the base fee of the node below broadcast for the channel id provided.

node="03ebc7280ff486f94cee51cff45a0fc521e9fe2560c02563ab191552fa90d4017d"
channel_id="6102289534222336"

# This lncli command allows the script to run against signet nodes for testing purposes, refer to it using $lncli.
# You may comment it out and use your own testing node if you would like, but this line *must* be uncommented when you push to test.
wd=$(pwd)
lncli="lncli -n=signet --rpcserver=boss2025.xyz:10007 --tlscertpath="$wd"/test/lnd2-tls.cert --macaroonpath="$wd"/test/lnd2-readonly.macaroon "
$lncli getchaninfo $channel_id | jq '.node2_policy.fee_base_msat'