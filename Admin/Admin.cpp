#include "../resources.h"

#include <iostream>
#include <fstream>
using namespace std;
using namespace seal;

void createKeys()
{
	cout << "Create Keys" << endl;

	//Define context <-> key parameters
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	CoeffModulus::BFVDefault(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(512);
	//parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);

	//Create key
	cout << "After context is made" << endl;
	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();

	//Send keys to files

	ofstream privateKeyFile;
	ofstream publicKeyFile;
  	
	privateKeyFile.open ("Admin/ElectionKeys/privateKey.txt");
	publicKeyFile.open ("Admin/ElectionKeys/publicKey.txt");  
	secret_key.save(privateKeyFile);
	public_key.save(publicKeyFile);
	
	privateKeyFile.close();
	publicKeyFile.close();
}

void createWeights(int NUMBERVOTERS)
{
	cout << "Create Weights" << endl;

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
	publicKeyFile.open("Admin/ElectionKeys/publicKey.txt");
	privateKeyFile.open("Admin/ElectionKeys/privateKey.txt");

	cout << "Load public key" << endl;
	public_key.load(context, publicKeyFile);
	secret_key.load(context, privateKeyFile);
    Decryptor decryptor(context, secret_key);
	Encryptor encryptor(context, public_key);

	Plaintext weight;
	Ciphertext encryptedWeight;
	ofstream myfile;
	char filename[25];
	char command[100];

	srand(time(NULL));
	int randvalue;
	for (int i=0; i<NUMBERVOTERS; i++){
		randvalue = rand() % (5 - 1 + 1) + 1;
		weight=encoder.encode(randvalue);	
		cout << "valor: " << randvalue << endl;
		sprintf(filename, "Admin/encryptedWeight_%i",i);
		myfile.open(filename);
		encryptor.encrypt(weight, encryptedWeight);
		encryptedWeight.save(myfile);
		myfile.close();
		//Move weight to Tally
		sprintf(command, "mv %s Tally/", filename);
		system(command);			
	}

	publicKeyFile.close();
	privateKeyFile.close();

}

int main(int argc, char *argv)
{
	if(argc != 4)
	{
		printf("Insert all parameters (NCandidates, NVoters, NTrustees");
		return 0;
	}

	int n_candidates = stoi(argv[1]), n_voters = stoi(argv[2]), n_trustees = stoi(argv[3]);

	if(!(n_candidates > 0 && n_voters > 0 && n_trustees > 0))
	{
		printf("Insert correct parameters");
		return 0;
	}

	createKeys();
	createWeights(n_voters);

	char command[100];
	sprintf(command, "./Admin/bash.sh %i %i %i", n_voters, n_candidates, n_trustees);
	system(command);			

	return 0;
}