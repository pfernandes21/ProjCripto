#include "../resources.h"

#include <iostream>
#include <fstream>

using namespace std;
using namespace seal;

int main(){
	cout << "Counter" << endl;

	int NUMBERCANDIDATES, NUMBERVOTERS;
	ifstream configFile;
	configFile.open("Config.txt");
	if(getline(configFile, line))
	{
		NUMBERCANDIDATES = stoi(line);
	}
	else
	{
		return 0;
	}

	if(getline(configFile, line))
	{
		NUMBERVOTERS = stoi(line);
	}
	else
	{
		return 0;
	}

	if(getline(configFile, line))
	{
		NUMBERTRUSTEES = stoi(line);
	}
	else
	{
		return 0;
	}

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
	publicKeyFile.open("Counter/publicKey.txt");
	cout << "Load public key" << endl;
	public_key.load(context, publicKeyFile);
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
		sprintf(shareName,"Trustees/Trustee%i/share%i.txt", i,i);
		trusteeShare.open(shareName);
		getline (trusteeShare, myText);
		allShares << myText << endl;
		trusteeShare.close();
	}
	allShares.close();

	//Take the first 3 shares and combine them
	sprintf(command,"head -n %i allShares.txt | secret-share-combine > password.txt", NUMBERTRUSTEES);
	system(command);
	
	system("openssl bf -d -in encriptedPrivateKey.txt -out decriptedPrivateKey.txt -pass file:password.txt");

	system("rm password.txt");
	system("rm allShares.txt");

	//Get the private Key
	ifstream privateKeyFile;
	privateKeyFile.open("decriptedPrivateKey.txt");
	secret_key.load(context, privateKeyFile);
    Decryptor decryptor(context, secret_key);
	
	//Fetch the accumulator and results:
	int controlValue = NUMBERVOTERS * NUMBERCANDIDATES;
	ifstream accumulatorFile;
	ifstream resultFile;
	Ciphertext accumulatorEncrypted;
	Plaintext accumulatorPlain;
	Ciphertext resultEncrypted;
	Plaintext resultPlain;
	int accumulatorValue, resultValue, winnerScore=0;
	int winner = -1;
	bool tie = false;
	string resultFileName;

	accumulatorFile.open("accumulator.txt");
	accumulatorEncrypted.load(context, accumulatorFile);
	decryptor.decrypt(accumulatorEncrypted, accumulatorPlain);
	accumulatorValue = encoder.decode_int32(accumulatorPlain);
		
	if(accumulatorValue != controlValue && false)
	{
		cout << "Election Compromised, abort election \n";
	}
	else
	{
		for(int i=0; i<NUMBERCANDIDATES; i++)
		{
			resultFileName = "resultCandidate_" + to_string(i) + ".txt";
			resultFile.open(resultFileName);
			resultEncrypted.load(context, resultFile);
			decryptor.decrypt(resultEncrypted, resultPlain);
			resultValue = encoder.decode_int32(resultPlain);
			if(resultValue > winnerScore)
			{
				winnerScore = resultValue;
				winner = i;
				tie = false;
			}
			else if(resultValue == winnerScore)
			{
				tie = true;
			}
			resultFile.close();
		}
		cout << "Winner is Candidate_" << to_string(winner) << " With : " << to_string(winnerScore) << endl;
	}
		
	publicKeyFile.close();
	privateKeyFile.close();

	return 0;
}