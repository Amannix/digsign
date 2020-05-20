#!/bin/bash

if [ $# -ne 1 ]
then
        echo -e "Wron number of arguments. Usage \n"
        echo -e "./gen_keys.sh <key_len_bits> \n"
else
        key_size=$1
        echo "Generate private key of size ${key_size} bits"
        openssl genpkey -algorithm RSA -out private_key.der -outform DER -pkeyopt rsa_keygen_bits:${key_size}
        openssl asn1parse  -in private_key.der -inform DER

        echo "Generate public key :"
        openssl rsa -pubout -in private_key.der -out public_key.der -inform DER -outform DER -RSAPublicKey_out
        openssl asn1parse  -in public_key.der -inform DER

        make clean
        make all

        echo "Convert private key to c:"
        ./convert -f private_key.der
        echo "Convert public key to c:"
        ./convert -f public_key.der
fi
