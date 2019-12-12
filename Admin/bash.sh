#!/bin/bash
#
#Initialize config file
echo "${2}\n${1}\n${3}" > 'Config.txt';
cd Admin/;
#
#Copy Election public key to Tally
cp ElectionKeys/publicKey.txt ../Voter/;
cp ElectionKeys/publicKey.txt ../Tally/;
cp ElectionKeys/publicKey.txt ../Counter/;
#Create Directories
rm -r CA;
mkdir CA;
chmod 0770 CA;
rm -r Certs;
mkdir Certs;
#
#Create CA certificate and send to Tally
echo "*****Create CA Certificate*****";
openssl genrsa -des3 -out CA/my-ca.key 2048;
openssl req -new -x509 -days 3650 -key CA/my-ca.key -out CA/my-ca.crt;
cp CA/my-ca.crt ../Tally/Certs/;
#
#Create certificate for voters
for (( i=1; i<=${1}; i++ ))
do
    echo "Create Certificate for Voter${i}";
    openssl genrsa -des3 -out client-cert${i}.key 1024;
    openssl rsa -in client-cert${i}.key -out clientPrivateKey${i}.key;
    openssl req -new -key client-cert${i}.key -out client-cert${i}.csr;
    openssl x509 -req -in client-cert${i}.csr -out client-cert${i}.crt -sha1 -CA CA/my-ca.crt -CAkey CA/my-ca.key -CAcreateserial -days 3650;
    openssl x509 -pubkey -noout -in client-cert${i}.crt > clientPublicKey${i}.key;
    openssl pkcs12 -export -in client-cert${i}.crt -inkey client-cert${i}.key -name 'User Cert' -out client-cert${i}.p12;
    openssl pkcs12 -in client-cert${i}.p12 -clcerts -nokeys -info;
    chmod 444 client-cert${i}.p12;
done
#Move to Certificates Directory
mv *.key Certs;
mv *.p12 Certs;
mv *.csr Certs;
mv *.crt Certs;
#
cd ../Voter;
#Reset vote count
echo "0" > 'id.txt';
#Create Voters Directories
for (( i=1; i<=${1}; i++ ))
do
    rm -r Voter${i};
    mkdir Voter${i};
done
cd ../Admin;
#
#Send keys and files to Voters
for (( i=1; i<=${1}; i++ ))
do
    #Send root CA cert to Voter
    cp CA/my-ca.crt ../Voter/Voter${i}/;
    #Send voter private key and certificate
    cp Certs/client-cert${i}.crt ../Voter/Voter${i}/;
    cp Certs/client-cert${i}.key ../Voter/Voter${i}/;
    cp Certs/clientPrivateKey${i}.key ../Voter/Voter${i}/;
    cp Certs/clientPublicKey${i}.key ../Voter/Voter${i}/;
    #Send Election public key to Voter
    cp ElectionKeys/publicKey.txt ../Voter/Voter${i}/electionPublicKey.txt;
done
#
#Encrypte private key with password
cd ElectionKeys;
echo "Insert Private Key Password:";
read pass;
echo ${pass} > 'password.txt';
openssl bf -e -in privateKey.txt -out encriptedPrivateKey.txt -pass file:password.txt
rm password.txt;
cd ..;
#
#Create password shares
source ~/.profile;
source ~/.cargo/env;
# Make NTrustees shares with recombination the same threshold
echo "Tyler Durden isn't real." | secret-share-split -n ${3} -t ${3} > shares.txt;
#
cd ..;
rm -r Trustees;
mkdir Trustees;
cd Trustees;
#Read shares from file
declare -i x=1;
while IFS= read -r line; 
do
    mkdir Trustee${x};
    touch Trustee${x}/share${x}.txt;
    echo ${line} >> Trustee${x}/share${x}.txt;
    ((x=x+1));
done < ../Admin/shares.txt
rm shares.txt;