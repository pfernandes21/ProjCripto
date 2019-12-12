#include "../resources.h"

#include <string>
#include <iostream>
#include <fstream>
#include <ctime>

using namespace std;
using namespace seal;

bool hasEnding (std::string const &fullString, std::string const &ending) 
{
	if (fullString.length() >= ending.length()) 
	{
		return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
	} 
	else 
	{
		return false;
	}
}

int main()
{
	cout << "Tally App" << endl;

	//SEAL Define context parameters
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
	ifstream electionPublicKeyFile;
	electionPublicKeyFile.open("Tally/publicKey.txt");
	cout << "Load public key" << endl;
	public_key.load(context, electionPublicKeyFile);
	Encryptor encryptor(context, public_key);

	electionPublicKeyFile.close();

	//Command for command line
	char command[300];

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();
	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();
	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

	// Grab number of votes to count
	int numberVotes;
	string line;
	//get id do voto no ficheiro
	ifstream IdFileIn("Voter/id.txt", ios::in);
	if (IdFileIn.is_open())
	{
		while (getline(IdFileIn, line))
		{
			numberVotes = stoi(line);
		}
		IdFileIn.close();
	}
	else
	{
		return 0;
	}

	cout << "Number of votes in the Ballot: " << numberVotes << endl;

	//Cicle for reading all votes in ballot

	string voteFileName;
	string signature;
	string voterKeyFileName;
	bool signatureCheck;
	bool voterIDCheck;
	bool authentic = false;
	bool fileExists = false;
	bool voteNumberCheck = false;
	string voterID, voterIDFromList;
	int voters[NUMBERVOTERS] = { -1};
	Ciphertext voteResults[NUMBERCANDIDATES];
	Ciphertext voterWeights[NUMBERVOTERS];

	//Fetch the voter Weights
	string voterWeightFileName;
	ifstream voterWeightFile;
	for (int n = 0; n < NUMBERVOTERS; n++) 
	{
		voterWeightFileName = "Tally/encryptedWeight_" + to_string(n);
		//Load encrypted weight
		voterWeightFile.open(voterWeightFileName);
		voterWeights[n].load(context, voterWeightFile);
		voterWeightFile.close();
	}

	//Initialize voterResults
	int aux = 0;
	Plaintext voteResults_plain(to_string(aux));
	for (int m = 0; m < NUMBERCANDIDATES; m++) 
	{
		encryptor.encrypt(voteResults_plain, voteResults[m]);
	}

	for (int j = 0; j < numberVotes; j++) 
	{
		voteFileName = "Ballot/vote" + to_string(j + 1) + ".txt";
		signature = "";
		signatureCheck = false;
		voterIDCheck = true;
		//Fetch vote
		std::ifstream voteFile(voteFileName);
		std::string vote((std::istreambuf_iterator<char>(voteFile)), std::istreambuf_iterator<char>());
		std::ofstream tempFile("signatureTemp.txt");
		std::ifstream voteEncryptedFile;

		//Read vote, and when reading files of encrypted votes open them
		// then add them in a file for later signature check
		istringstream ss(vote);
		do {
			// Read a word
			string word;
			ss >> word;

			if (hasEnding(word, ".txt\"")) 
			{
				//delete the " " from the begining and end
				word.erase(word.begin());
				word.erase(word.end() - 1);
				//add path to directorie
				word = "Ballot/" + word;
				//OpenEncrypted vote file and copy its data to tempFile
				voteEncryptedFile.open(word);
				std::string dataEncrypted((std::istreambuf_iterator<char>(voteEncryptedFile)), std::istreambuf_iterator<char>());
				tempFile << dataEncrypted;
				//this is to guarantee that it fetches only the signature check after
				signatureCheck = true;
				voteEncryptedFile.close();
				continue;
			}
			if (signatureCheck)
			{
				signature = signature + word ;
				signature = signature + '\n';
			}
			if (voterIDCheck)
			{
				voterIDCheck = false;
				voterID = word;
			}
		} while (ss);

		voterKeyFileName = "Voter/Voter" + voterID + "/clientPublicKey" + voterID + ".key";

		//Fetch  public key of voter in order to check signature
		std::ifstream publicKeyFile(voterKeyFileName);
		std::string mypublicKey((std::istreambuf_iterator<char>(publicKeyFile)), std::istreambuf_iterator<char>());

		//Grab tempFile created to
		std::ifstream tempInputFile("signatureTemp.txt");
		//Convert string to char*
		// declaring character array :
		char charSignature[signature.length()];

		for (int i = 0; i < signature.length() + 1; i++) 
		{
			charSignature[i] = signature[i];
		}

		//Fetch data from temporary file
		std::string dataTempFile((std::istreambuf_iterator<char>(tempInputFile)), std::istreambuf_iterator<char>());
		//Check signature with encrypted data, public key and signature in vote
		authentic = verifySignature(mypublicKey, dataTempFile, charSignature);

		if ( authentic ) 
		{
			std::cout << "Authentic" << std::endl;
			//get id do voto no ficheiro
			ofstream lastVotesOut("lastVotes.txt", ios::app);
			ifstream lastVotesIn("lastVotes.txt");

			if (lastVotesIn.is_open() && lastVotesOut.is_open())
			{
				while (getline(lastVotesIn, line))
				{
					cout << "line from lastVote: " << line  << endl;
					//fileExists = true;
					stringstream iss(line);
					voterIDCheck = false;
					voteNumberCheck = false;
					voterIDFromList = "Voter: " + voterID;

				}

				lastVotesOut << "Voter: " << voterID << " " << "VoteNumber: " << to_string(j + 1) << endl;
				voters[stoi(voterID)] = j + 1;

				lastVotesOut.close();
				lastVotesIn.close();
			}
			else
			{
				cout << "Last votes not opened \n";
				return 0;
			}
		} 
		else 
		{
			std::cout << "Not Authentic" << std::endl;
		}

		/* Clean up */
		tempFile.close();
		voteFile.close();
		publicKeyFile.close();
		tempInputFile.close();
	}

	//Compute checkSum for each vote and add it to an accumulator
	//Cycle through the last votes of each voter
	int lastVote;
	int x = 0;
	Plaintext accumulator_plain(to_string(x));
	//Encrypt plain text
	Ciphertext accumulator;
	encryptor.encrypt(accumulator_plain, accumulator);

	for (int k = 0; k < NUMBERVOTERS ; k++) 
	{
		lastVote = voters[k];
		voteFileName = "Ballot/vote" + to_string(lastVote) + ".txt";
		cout << "Opening for checksum : " << voteFileName << endl;
		std::ifstream voteFile(voteFileName);
		std::string vote((std::istreambuf_iterator<char>(voteFile)), std::istreambuf_iterator<char>());
		//Read vote get encrypted files and add them to checksum
		//Cycle through each vote cyphertexts
		istringstream ss(vote);
		do {
				// Read a word
				string word;
				ss >> word;

				//Compute add the encrypted value of the vote to the accumulator
				if (hasEnding(word, ".txt\"")) 
				{
					Ciphertext multiply_result;
					ifstream voteEncryptedFile;
					//delete the " " from the begining and end
					word.erase(word.begin());
					word.erase(word.end() - 1);
					//add path to directorie
					word = "Ballot/" + word;
					//Load encrypted vote
					voteEncryptedFile.open(word);
					cout << "encrypted vote to open: " << word << endl;
					//Cut word down to obtain Id of candidate
					word.erase(17);
					word.erase(word.begin(), word.end() - 1);
					cout << "ID candidate: " << word << endl;
					// that will have all the votes of that candidate ( do a vector of ciphetext w/size of
					// number of candidates)
					Ciphertext encryptedVote;
					encryptedVote.load(context, voteEncryptedFile);
					evaluator.add_inplace(accumulator, encryptedVote);
					//multiply weight by encrypted vote and add to encrypted file
					evaluator.multiply(encryptedVote, voterWeights[k], multiply_result);
					evaluator.add_inplace(voteResults[stoi(word)], multiply_result);
					voteEncryptedFile.close();
					continue;
				}
		} while (ss);
	}

	//Output result files and accumulator
	ofstream resultFile;
	ofstream accumulatorFile;
	string resultFileName;

	accumulatorFile.open("accumulator.txt");
	accumulator.save(accumulatorFile);

	for (int b = 0; b < NUMBERCANDIDATES; b++) 
	{
		resultFileName = "resultCandidate_" + to_string(b) + ".txt";
		resultFile.open(resultFileName);
		voteResults[b].save(resultFile);
		resultFile.close();
	}

	accumulatorFile.close();

	/*
	ifstream electionPrivateKeyFile;
	electionPrivateKeyFile.open("Administrator/electionKeys/privateKey.txt");
	cout << "Load private key" << endl;
	secret_key.load(context, electionPrivateKeyFile);
	Decryptor decryptor(context, secret_key);

	//Decryption
	Plaintext accumulator_decrypted;
	Plaintext results_decrypted[NUMBERCANDIDATES];
	decryptor.decrypt(accumulator, accumulator_decrypted);
	decryptor.decrypt(voteResults[0], results_decrypted[0]);
	decryptor.decrypt(voteResults[1], results_decrypted[1]);

	cout << "Ammo available "<< decryptor.invariant_noise_budget(accumulator) <<endl;
	cout << "Ammo available result 0 "<< decryptor.invariant_noise_budget(voteResults[0]) <<endl;
	cout << "Ammo available result 1 "<< decryptor.invariant_noise_budget(voteResults[1]) <<endl;


	cout << "Accumulator : " << encoder.decode_int32(accumulator_decrypted) <<endl;
	cout << "result 0 : " << encoder.decode_int32(results_decrypted[0]) <<endl;
	cout << "result 1 : " << encoder.decode_int32(results_decrypted[1]) <<endl;
	electionPrivateKeyFile.close();
	*/

	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

	/* Remove error strings */
	ERR_free_strings();

	return 0;
}
