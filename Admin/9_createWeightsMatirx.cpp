#include "examples.h"

#include <iostream>
#include <fstream>

#define NUMBERVOTERS 2

using namespace std;
using namespace seal;

void createWeights(){
	cout << "Load keys" << endl;

	//Define context parameters
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 4096;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	CoeffModulus::BFVDefault(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(512);

	//for matrixes
	//parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

	auto context = SEALContext::Create(parms);



	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();
    	Evaluator evaluator(context);

	IntegerEncoder encoder(context);
	//BatchEncoder batch_encoder(context);
	//size_t slot_count = batch_encoder.slot_count();
	//size_t row_size = slot_count / 2;
    	//cout << "Plaintext matrix row size: " << row_size << endl;
	//vector<uint64_t> weight_matrix(slot_count, 0ULL);

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

	srand(time(NULL));
	int randvalue;
	for (int i=0; i<NUMBERVOTERS; i++){
		randvalue = rand() % (5 - 1 + 1) + 1;
		weight_matrix[i]=randvalue;	
		cout << "valor: " << randvalue << endl;
	}

	//print_matrix(weight_matrix, row_size);

	//encode the matrix
	Plaintext plain_matrix;
    	batch_encoder.encode(weight_matrix, plain_matrix);

	//Decode matrix
	//vector<uint64_t> pod_result;
 	//cout << "    + Decode plaintext matrix ...... Correct." << endl;
    	//batch_encoder.decode(plain_matrix, pod_result);
    	//print_matrix(pod_result, row_size);

	//Encrypt matrix
	Ciphertext encrypted_matrix;
    	encryptor.encrypt(plain_matrix, encrypted_matrix);
    	cout << "    + Noise budget in encrypted_matrix: " << decryptor.invariant_noise_budget(encrypted_matrix) << " bits" << endl;

	ofstream myfile;

	myfile.open("encryptedWeights.txt");
	encrypted_matrix.save(myfile);
	myfile.close();
	cout << "End and exit" << endl;

	publicKeyFile.close();
	privateKeyFile.close();

}
