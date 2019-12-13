#!/bin/bash
value=$(<signatureTemp.txt);
echo "$value" | openssl dgst -sha512 > mega.txt;