#include "resources.h"

using namespace std;
using namespace seal;

void counter(int NUMBERCANDIDATES, int NUMBERVOTERS, int NUMBERTRUSTEES)
{
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
	SecretKey secret_key = keygen.secret_key();
	Evaluator evaluator(context);
	IntegerEncoder encoder(context);

	char shareName[100];
	char command[200];

	// Create a text string, which is used to output the text file
	string myText;

	// Read from the text file
	ofstream allShares("allShares.txt");
	ifstream trusteeShare;

	//opening each trustee document
	for (int i = 1; i <= NUMBERTRUSTEES; i++)
	{
		sprintf(shareName, "Trustees/Trustee%i/share%i.txt", i, i);
		trusteeShare.open(shareName);
		getline(trusteeShare, myText);
		allShares << myText << endl;
		trusteeShare.close();
	}
	allShares.close();

	//Take the first 3 shares and combine them
	sprintf(command, "head -n %i allShares.txt | secret-share-combine > password.txt", NUMBERTRUSTEES);
	system(command);

	sprintf(command, "openssl bf -d -in Admin/ElectionKeys/encriptedPrivateKey.txt -out decriptedPrivateKey.txt -pass file:password.txt");
	system(command);

	sprintf(command, "rm password.txt");
	system(command);

	//Get the private Key
	ifstream privateKeyFile;
	privateKeyFile.open("decriptedPrivateKey.txt");
	secret_key.load(context, privateKeyFile);
	Decryptor decryptor(context, secret_key);

	string line;
	ifstream actualVotersFile("Counter/actualVoters.txt", ios::in);
	if (actualVotersFile.is_open())
	{
		while (getline(actualVotersFile, line))
		{
			NUMBERVOTERS = stoi(line);
		}
		actualVotersFile.close();
	}
	else
	{
		return;
	}

	//Fetch the accumulator and results:
	int controlValue = NUMBERVOTERS * NUMBERCANDIDATES;
	ifstream accumulatorFile;
	ifstream resultFile;
	Ciphertext accumulatorEncrypted;
	Plaintext accumulatorPlain;
	Ciphertext resultEncrypted;
	Plaintext resultPlain;
	int accumulatorValue, resultValue, winnerScore = 0;
	int winner = -1;
	bool tie = false;
	string resultFileName;

	accumulatorFile.open("accumulator.txt");
	accumulatorEncrypted.load(context, accumulatorFile);
	decryptor.decrypt(accumulatorEncrypted, accumulatorPlain);
	accumulatorValue = encoder.decode_int32(accumulatorPlain);

	if (accumulatorValue != controlValue)
	{
		cout << "Election Compromised, abort election \n";
	}
	else
	{
		for (int i = 0; i < NUMBERCANDIDATES; i++)
		{
			resultFileName = "resultCandidate_" + to_string(i) + ".txt";
			resultFile.open(resultFileName);
			resultEncrypted.load(context, resultFile);
			decryptor.decrypt(resultEncrypted, resultPlain);
			resultValue = encoder.decode_int32(resultPlain);
			if (resultValue > winnerScore)
			{
				winnerScore = resultValue;
				winner = i;
				tie = false;
			}
			else if (resultValue == winnerScore)
			{
				tie = true;
			}
			resultFile.close();
		}
		if(tie) cout << "Tie" << endl;
		else cout << "Winner is Candidate_" << to_string(winner) << " With : " << to_string(winnerScore) << endl;
	}

	accumulatorFile.close();
	privateKeyFile.close();
}