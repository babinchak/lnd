#!/bin/bash
fuzztime=3s

echo ------- Running brontide fuzz tests $fuzztime each -------
cd brontide
declare -a StringArray=("Fuzz_random_actone"
                        "Fuzz_random_actthree"
                        "Fuzz_random_acttwo"
                        "Fuzz_random_init_decrypt"
                        "Fuzz_random_init_enc_dec"
                        "Fuzz_random_init_encrypt"
                        "Fuzz_random_resp_decrypt"
                        "Fuzz_random_resp_enc_dec"
                        "Fuzz_random_resp_encrypt"
                        "Fuzz_static_actone"
                        "Fuzz_static_actthree"
                        "Fuzz_static_acttwo"
                        "Fuzz_static_init_decrypt"
                        "Fuzz_static_init_enc_dec"
                        "Fuzz_static_init_encrypt"
                        "Fuzz_static_resp_decrypt"
                        "Fuzz_static_resp_enc_dec"
                        "Fuzz_static_resp_encrypt")

for val in "${StringArray[@]}"; do
        echo running $val
        go test -fuzz $val -fuzztime $fuzztime
done

cd ..

echo ------- Running lnwire fuzz tests $fuzztime each -------
cd lnwire
declare -a StringArray=("Fuzz_accept_channel"
                        "Fuzz_announce_channels"
                        "Fuzz_channel_announcement"
                        "Fuzz_channel_reestablish"
                        "Fuzz_channel_update"
                        "Fuzz_closing_signed"
                        "Fuzz_commit_sig"
                        "Fuzz_error"
                        "Fuzz_funding_created"
                        "Fuzz_funding_locked"
                        "Fuzz_funding_signed"
                        "Fuzz_gossip_timestamp_range"
                        "Fuzz_init"
                        "Fuzz_node_announcement"
                        "Fuzz_open_channel"
                        "Fuzz_ping"
                        "Fuzz_pong"
                        "Fuzz_query_channel_range"
                        "Fuzz_query_short_chan_ids_zlib"
                        "Fuzz_query_short_chan_ids"
                        "Fuzz_reply_channel_range_zlib"
                        "Fuzz_reply_channel_range"
                        "Fuzz_reply_short_chan_ids_end"
                        "Fuzz_revoke_and_ack"
                        "Fuzz_shutdown"
                        "Fuzz_update_add_htlc"
                        "Fuzz_update_fail_htlc"
                        "Fuzz_update_fail_malformed_htlc"
                        "Fuzz_update_fee"
                        "Fuzz_update_fulfill_htlc")
cd ..

for val in "${StringArray[@]}"; do
        echo running $val
        go test -fuzz $val -fuzztime $fuzztime
done

echo ------- Running wtwire fuzz tests $fuzztime each -------
cd watchtower/wtwire
declare -a StringArray=("Fuzz_create_session_reply"
                        "Fuzz_create_session"
                        "Fuzz_delete_session_reply"
                        "Fuzz_delete_session"
                        "Fuzz_error"
                        "Fuzz_init"
                        "Fuzz_state_update_reply"
                        "Fuzz_state_update")
for val in "${StringArray[@]}"; do
        echo running $val
        go test -fuzz $val -fuzztime $fuzztime
done
cd ../..

echo ------- Running zpay32 fuzz tests $fuzztime each -------
cd zpay32
declare -a StringArray=("Fuzz_decode"
                        "Fuzz_encode")
for val in "${StringArray[@]}"; do
        echo running $val
        go test -fuzz $val -fuzztime $fuzztime
done
cd ..