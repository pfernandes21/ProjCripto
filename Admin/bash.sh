#Create CA certificate and send to Tally app
rm -r Admin/CA
mkdir Admin/CA
chmod 0770 CA;
echo "Create CA Certificates"
openssl genrsa -des3 -out Admin/CA/my-ca.key 2048;
openssl req -new -x509 -days 3650 -key Admin/CA/my-ca.key -out Admin/CA/my-ca.crt;
cp Admin/CA/my-ca.crt TallyApp/Certs/;
#
#Create certificate for voter0
# openssl genrsa -des3 -out client-cert0.key 1024;
# openssl rsa -in client-cert0.key -out clientPrivateKey0.key;
# openssl req -new -key client-cert0.key -out client-cert0.csr;
# openssl x509 -req -in client-cert0.csr -out client-cert0.crt -sha1 -CA CA/my-ca.crt -CAkey CA/my-ca.key -CAcreateserial -days 3650;
# openssl x509 -pubkey -noout -in client-cert0.crt > clientPublicKey0.key;
# openssl pkcs12 -export -in client-cert0.crt -inkey client-cert0.key -name 'User Cert' -out client-cert0.p12;
# openssl pkcs12 -in client-cert0.p12 -clcerts -nokeys -info;
# chmod 444 client-cert0.p12;
# mv *.key Certs;
# mv *.p12 Certs;
# mv *.csr Certs;
# mv *.crt Certs;
# #
# #Create certificate for voter1
# openssl genrsa -des3 -out client-cert1.key 1024;
# openssl rsa -in client-cert1.key -out clientPrivateKey1.key;
# openssl req -new -key client-cert1.key -out client-cert1.csr;
# openssl x509 -req -in client-cert1.csr -out client-cert1.crt -sha1 -CA CA/my-ca.crt -CAkey CA/my-ca.key -CAcreateserial -days 3650;
# openssl x509 -pubkey -noout -in client-cert1.crt > clientPublicKey1.key;
# openssl pkcs12 -export -in client-cert1.crt -inkey client-cert1.key -name 'User Cert' -out client-cert1.p12;
# openssl pkcs12 -in client-cert1.p12 -clcerts -nokeys -info;
# chmod 444 client-cert1.p12;
# mv *.key Certs;
# mv *.p12 Certs;
# mv *.csr Certs;
# mv *.crt Certs;
# #
# #Send root CA cert to Voter0
# cp CA/my-ca.crt ../VoterApp/client0/;
# #Send voter0 private key and certificate
# cp Certs/client-cert0.crt ../VoterApp/client0/;
# cp Certs/client-cert0.key ../VoterApp/client0/;
# cp Certs/clientPrivateKey0.key ../VoterApp/client0/;
# cp Certs/clientPublicKey0.key ../VoterApp/client0/;
# #Send Election public key to Voter0
# cp electionKeys/publicKey.txt ../VoterApp/client0/electionPublicKey.txt;
# #
# #Send root CA cert to Voter0
# cp CA/my-ca.crt ../VoterApp/client0/;
# #Send voter0 private key and certificate
# cp Certs/client-cert0.crt ../VoterApp/client0/;
# cp Certs/client-cert0.key ../VoterApp/client0/;
# cp Certs/clientPrivateKey0.key ../VoterApp/client0/;
# cp Certs/clientPublicKey0.key ../VoterApp/client0/;
# #Send Election public key to Voter0
# cp electionKeys/publicKey.txt ../VoterApp/client0/electionPublicKey.txt;
# #
# #Send root CA cert to Voter1
# cp CA/my-ca.crt ../VoterApp/client1/;
# #Send voter1 private key and certificate
# cp Certs/client-cert1.crt ../VoterApp/client1/;
# cp Certs/client-cert1.key ../VoterApp/client1/;
# cp Certs/clientPrivateKey1.key ../VoterApp/client1/;
# cp Certs/clientPublicKey1.key ../VoterApp/client1/;
# #Send Election public key to Voter1
# cp electionKeys/publicKey.txt ../VoterApp/client1/electionPublicKey.txt;
# #
# #encryptar private key com password
