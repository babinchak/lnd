#!/bin/bash
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
cd brontide

for val in "${StringArray[@]}"; do
        echo running $val
        go test -fuzz $val -fuzztime 30s
done

cd ..