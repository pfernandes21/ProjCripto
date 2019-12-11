#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string>
#include <iostream>
#include "defines.h"
#include <fstream>

void createDirectories();
void createVotersDirectories(int );
void sendInfoToVoters(int );
void createTrusteesDirectories();
void createElectionKeys();
void createWeights();

using namespace std;

int main(int argc, char *argv[])
{
	
	int numberVoters, numberTrustees;
	/*if( argc == 2 ) {
    	printf("The argument supplied is %s \n", argv[1]);
   	}
   	else if( argc > 2 ) {
    	printf("Too many arguments supplied.\n");
	exit(0);
   	}
	else {
    	printf("One argument expected.\n");
	exit(0);
   	}*/
	
	//Uncomment to create directories
	//createDirectories();
	
	char command[COMMANDLENGTH];
	numberVoters = NUMBERVOTERS; 
	//atoi(argv[1]);
	//printf("voters num = %i \n", numberVoters);
/*	
	// Create CA, its certificate and send it to Tally app	
	sprintf(command,"chmod 0770 %s", CAPath);
   	system(command);
    	sprintf(command,"openssl genrsa -des3 -out %s/my-ca.key 2048", CAPath);
   	system(command);
    	sprintf(command,"openssl req -new -x509 -days 3650 -key %s/my-ca.key -out %s/my-ca.crt", CAPath, CAPath);
    	system(command);
    	sprintf(command,"cp %s/my-ca.crt %s/TallyApp/Certs/", CAPath, sourcePath);
    	system(command);
	
	
	//Create certificate for each voter
	
	
	for(int i=0; i<numberVoters; i++){
	
		//Create client key
		printf("\n-----------------------\n Creating client key \n ------------------------ \n");
    		sprintf(command,"openssl genrsa -des3 -out client-cert%i.key 1024", i);
    		system(command);
    	
		//Create file with private key only
		printf("\n-----------------------\n Creating file with private key only \n ------------------------ \n");
    		sprintf(command,"openssl rsa -in client-cert%i.key -out clientPrivateKey%i.key", i,i);
    		system(command);

    		//Create client certificate request
    		printf("\n-----------------------\n Creating client certificate request\n ------------------------ \n");
    		sprintf(command,"openssl req -new -key client-cert%i.key -out client-cert%i.csr", i,i);
    		system(command);
    	
    		//Sign certificate
    		printf("\n-----------------------\n Signing Certificate\n ------------------------ \n");
    		sprintf(command,"openssl x509 -req -in client-cert%i.csr -out client-cert%i.crt -sha1 -CA %s/my-ca.crt -CAkey %s/my-ca.key -CAcreateserial -days 3650", i,i, CAPath, CAPath);
    		system(command);

		//Create file with public key
		sprintf(command,"openssl x509 -pubkey -noout -in client-cert%i.crt > clientPublicKey%i.key", i, i);
    		system(command);
		
    	
    		//Create PKCS12 file
    		printf("\n-----------------------\n Creating PKCS12\n ------------------------ \n");
		sprintf(command,"openssl pkcs12 -export -in client-cert%i.crt -inkey client-cert%i.key -name 'User Cert' -out client-cert%i.p12", i,i,i);
    		system(command);
    	
    		//Output key information no private keys or CA certificate outputs
    		//printf("\n-----------------------\n Controling output\n ------------------------ \n");
		//sprintf(command,"openssl pkcs12 -in client-cert%i.p12 -clcerts -nokeys -info", i);
    		//system(command);
    	
    		printf("\n-----------------------\n Make PKCS12 readable accessible\n ------------------------ \n");
		sprintf(command,"chmod 444 client-cert%i.p12", i);
    		system(command);
    	
    		printf("\n-----------------------\n Moving certs\n ------------------------ \n");
	    	sprintf(command,"mv *.key %s/Administrator/Certs",sourcePath);
	    	system(command);
	    	sprintf(command,"mv *.p12 %s/Administrator/Certs",sourcePath);
	    	system(command);
	    	sprintf(command,"mv *.csr %s/Administrator/Certs",sourcePath);
	    	system(command);
	    	sprintf(command,"mv *.crt %s/Administrator/Certs",sourcePath);
	    	system(command);
	}
	
	
*/
	//Create election keys and move them
/*	createElectionKeys();
	
	// Send each voter app the root CA certificate, voter private key 
	// and certificate, election public key.
	
	createVotersDirectories(numberVoters);
	sendInfoToVoters(numberVoters);


*/	
	//Encrypt private key file with a password
	//NOT WORKING
	//NOT WORKING
	//NOT WORKING

	/*string pass, passdecrypt;
	cout << "Type a password: \n"; // Type a number and press enter
	getline(cin, pass); // Get user input from the keyboard
	cout << "Your password is " << pass << endl; // Display the input value
	sprintf(command,"openssl enc -aes-128-cbc -md md5 -e -in %s/Administrator/electionKeys/privateKey.txt -out %s/Administrator/electionKeys/encriptedPrivateKey.txt -k '%s' -p", sourcePath, sourcePath, pass);
    	system(command);

	cout << "Type a password: \n"; // Type a number and press enter
	getline(cin, passdecrypt); // Get user input from the keyboard
sprintf(command,"openssl enc -aes-128-cbc -md md5 -d -in %s/Administrator/electionKeys/encriptedPrivateKey.txt -out %s/Administrator/electionKeys/decriptedPrivateKey.txt -k '%s' -p", sourcePath, sourcePath, passdecrypt);
    	system(command);*/

	sprintf(command,"%s",sealPath);
    	system(command);

	
	
}


void createWeights(){
	printf("------------- Creating Weights --------------------\n");

	int weight[NUMBERVOTERS];
	srand(time(NULL));
	int randvalue;
	
	for (int i=0; i<NUMBERVOTERS; i++){
		randvalue = rand() % (5 - 1 + 1) + 1;
		weight[i]=randvalue;	
	}
	ofstream weights;
	weights.open("weights.txt");
	for(int count = 0; count < NUMBERVOTERS; count ++){
        	weights << weight[count] << "\n" ;
    	}
   	weights.close();

}


void createDirectories(){
	char command[COMMANDLENGTH];
	printf("\n------------------------\nCreating Directories\n--------------------\n");
	sprintf(command,"mkdir %s/Administrator", sourcePath);
	system(command);
	sprintf(command,"mkdir %s/Administrator/CA", sourcePath);
	system(command);
	sprintf(command,"mkdir %s/Ballot", sourcePath);
	system(command);
	sprintf(command,"mkdir %s/Administrator/Certs", sourcePath);
	system(command);
	sprintf(command,"mkdir %s/Administrator/electionKeys", sourcePath);
	system(command);
	sprintf(command,"mkdir %s/TallyApp", sourcePath);
	system(command);
	sprintf(command,"mkdir %s/TallyApp/Certs", sourcePath);
	system(command);
	createTrusteesDirectories();

}

void createTrusteesDirectories(){
	char command[COMMANDLENGTH];
	printf("\n------------------------\nCreating Trustees directories\n-------------------\n");
	for(int i=0; i<NUMBERTRUSTEES; i++){
		sprintf(command,"mkdir %s/trustee%i", sourcePath,i);
    	system(command);
	}
}

void createVotersDirectories(int number){
	char command[COMMANDLENGTH];
	printf("\n------------------------\nCreating voters directories\n--------------------\n");
	for(int i=0; i<number; i++){
		sprintf(command,"mkdir %s/client%i", sourcePath,i);
    	system(command);
	}
}

void sendInfoToVoters(int number){
	char command[COMMANDLENGTH];
	printf("\n------------------------\nSending info to voters\n--------------------\n");
	for(int i=0; i<number; i++){
		//Send root CA cert
		sprintf(command,"cp %s/my-ca.crt %s/client%i/", CAPath, sourcePath, i);
		system(command);	
		//Send voter private key and certificate
		sprintf(command,"cp %s/Administrator/Certs/client-cert%i.crt %s/client%i/", sourcePath, i, sourcePath,i);
		system(command);
		sprintf(command,"cp %s/Administrator/Certs/client-cert%i.key %s/client%i/", sourcePath, i, sourcePath,i);
		system(command);
		sprintf(command,"cp %s/Administrator/Certs/clientPrivateKey%i.key %s/client%i/", sourcePath, i, sourcePath,i);
		system(command);
		sprintf(command,"cp %s/Administrator/Certs/clientPublicKey%i.key %s/client%i/", sourcePath, i, sourcePath,i);
		system(command);	
		//Send Election public key
		sprintf(command,"cp %s/Administrator/electionKeys/publicKey.txt %s/client%i/electionPublicKey.txt",sourcePath, sourcePath,i);
		system(command);
	}
}

void createElectionKeys(){
	char command[COMMANDLENGTH];
	sprintf(command,"%s",sealPath);
    	system(command);
	sprintf(command,"mv privateKey.txt %s/Administrator/electionKeys/",sourcePath);
    	system(command);
	sprintf(command,"mv publicKey.txt %s/Administrator/electionKeys/",sourcePath);
    	system(command);
}
