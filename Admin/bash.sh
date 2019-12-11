cd Admin/;
#
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
cp CA/my-ca.crt TallyApp/Certs/;
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
cd ../VoterApp;
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
    cp CA/my-ca.crt ../VoterApp/Voter${i}/;
    #Send voter private key and certificate
    cp Certs/client-cert${i}.crt ../VoterApp/Voter${i}/;
    cp Certs/client-cert${i}.key ../VoterApp/Voter${i}/;
    cp Certs/clientPrivateKey${i}.key ../VoterApp/Voter${i}/;
    cp Certs/clientPublicKey${i}.key ../VoterApp/Voter${i}/;
    #Send Election public key to Voter
    cp ElectionKeys/publicKey.txt ../VoterApp/Voter${i}/electionPublicKey.txt;
done
#
#Encrypte private key with password
echo "Insert Private Key Password:";
read pass;
openssl enc -aes-128-cbc -md md5 -e -in ElectionKeys/privateKey.txt -out ElectionKeys/encriptedPrivateKey.txt -k $pass -p;
#
#Create password shares
source ~/.profile;
source ~/.cargo/env;
# Make 4 shares with recombination threshold 3
echo "Tyler Durden isn't real." | secret-share-split -n 4 -t 3 > shares.txt;
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