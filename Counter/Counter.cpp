#include "../resources.h"

#include <iostream>
#include <fstream>

using namespace std;
using namespace seal;

void counter(){
	cout << "Counter" << endl;

	//Define context parameters
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	CoeffModulus::BFVDefault(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(512);
	auto context = SEALContext::Create(parms);

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
    Evaluator evaluator(context);
	IntegerEncoder encoder(context);

	//Load key and Weights
	ifstream publicKeyFile;
	ifstream privateKeyFile;
	publicKeyFile.open("Administrator/electionKeys/publicKey.txt");
	privateKeyFile.open("Administrator/electionKeys/privateKey.txt");
	cout << "Load public key" << endl;
	public_key.load(context, publicKeyFile);
	secret_key.load(context, privateKeyFile);
    Decryptor decryptor(context, secret_key);
	Encryptor encryptor(context, public_key);

	char shareName[100];
	char command[200];

	// Create a text string, which is used to output the text file
	string myText;

	// Read from the text file
	ofstream allShares("allShares.txt");
	ifstream trusteeShare;
	

	//opening each trustee document
	for(int i=0; i<NUMBERTRUSTEES; i++)
	{
		sprintf(shareName,"trustee%i/share%i.txt", i,i);
		trusteeShare.open(shareName);
		getline (trusteeShare, myText);
		allShares << myText << endl;
		trusteeShare.close();
	}

	allShares.close();

	//Take the first 3 shares and combine them
	sprintf(command,"head -n 3 allShares.txt | secret-share-combine > password.txt");
	system(command);

	string encryptionPass;
	ifstream passwordFile("password.txt");
	getline(passwordFile, encryptionPass);

	sprintf(command,"openssl bf -d -in encriptedPrivateKey.txt -out decriptedPrivateKey.txt -pass pass:%s", encryptionPass);
	system(command);
	
	publicKeyFile.close();
	privateKeyFile.close();
}
