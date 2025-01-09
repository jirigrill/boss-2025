#!/bin/bash
# Fill in lncli commands to lookup the base fee of the node below broadcast for the channel id provided.

node="037c3565e3c335886e44082b1cf14e081e1a030605b5b7925680954c2bc6ea1394"
channel_id="2005509209128960"

# This lncli command allows the script to run against signet nodes for testing purposes, refer to it using $lncli.
# You may comment it out and use your own testing node if you would like, but this line *must* be uncommented when you push to test.
wd=$(pwd)
lncli="lncli -n=signet --rpcserver=boss2025.xyz:10009 --tlscertpath="$wd"/test/lnd0-tls.cert --macaroonpath="$wd"/test/lnd0-readonly.macaroon "
