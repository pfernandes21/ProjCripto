#include "resources.h"

using namespace std;
using namespace seal;

bool compareTimestamps(std::string, std::string);

bool hasEnding(std::string const &fullString, std::string const &ending)
{
	if (fullString.length() >= ending.length())
	{
		return (0 == fullString.compare(fullString.length() - ending.length(), ending.length(), ending));
	}
	else
	{
		return false;
	}
}

void tally(int NUMBERCANDIDATES, int NUMBERVOTERS, int NUMBERTRUSTEES)
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
	Evaluator evaluator(context);

	//Load key and Weights
	ifstream electionPublicKeyFile;
	electionPublicKeyFile.open("Tally/publicKey.txt");
	cout << "Load public key" << endl;
	public_key.load(context, electionPublicKeyFile);
	Encryptor encryptor(context, public_key);

	electionPublicKeyFile.close();

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
		return;
	}

	cout << "Number of votes in the Ballot: " << numberVotes << endl;

	string lastTimestamps[NUMBERVOTERS] = {"0"};
	string voteFileName;
	string signature;
	string voterKeyFileName;
	string voterID;
	bool signatureCheck;
	bool voterIDCheck;
	bool authentic = false;
	bool fileExists = false;;
	int voters[NUMBERVOTERS] = {0};

	Ciphertext voteResults[NUMBERCANDIDATES];
	Ciphertext voterWeights[NUMBERVOTERS];

	//Fetch the voter Weights
	string voterWeightFileName;
	ifstream voterWeightFile;
	
	//Initialize voterResults
	Plaintext voteResults_plain(to_string(0));
	for (int m = 0; m < NUMBERCANDIDATES; m++)
	{
		encryptor.encrypt(voteResults_plain, voteResults[m]);
	}

	bool firstWord;
	string timestamp;
	for (int j = 0; j < numberVotes; j++)
	{
		voteFileName = "Ballot/vote" + to_string(j+1) + ".txt";
		signature = "";
		signatureCheck = false;
		voterIDCheck = true;
		firstWord = true;
		//Fetch vote
		std::ifstream voteFile(voteFileName);
		std::string vote((std::istreambuf_iterator<char>(voteFile)),
						 std::istreambuf_iterator<char>());

		std::ofstream tempFile("signatureTemp.txt");
		std::ifstream voteEncryptedFile;
		
		//Read vote, and when reading files of encrypted votes open them
		// then add them in a file for later signature check
		istringstream ss(vote);
		bool valid = true;
		do
		{
			// Read a word
			string word;
			ss >> word;
			//fetch timestamp
			if (firstWord)
				firstWord = false;

			if (hasEnding(word, ".txt\""))
			{
				int id, hour, minute, second;

				//delete the " " from the begining and end
				word.erase(word.begin());
				word.erase(word.end() - 1);
				//add path to directorie
				word = "Ballot/" + word;
				sscanf( word.c_str(), "Ballot/%d,%d,%d,%d.txt", &hour, &minute, &second, &id);
				if(id >= NUMBERCANDIDATES) valid = false;
				//OpenEncrypted vote file and copy its data to tempFile
				voteEncryptedFile.open(word);
				std::string dataEncrypted((std::istreambuf_iterator<char>(voteEncryptedFile)),
										  std::istreambuf_iterator<char>());

				tempFile << dataEncrypted;
				//this is to guarantee that it fetches only the signature check after
				signatureCheck = true;
				voteEncryptedFile.close();
				continue;
			}

			if (signatureCheck)
			{
				signature = signature + word;
				signature = signature + '\n';
				continue;
			}
			else if (voterIDCheck)
			{
				voterIDCheck = false;
				voterID = word;
				continue;
			}
			else if (!firstWord)
			{
				timestamp = word;
				continue;
			}
		} while (ss);

		tempFile << timestamp;

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
		std::string dataTempFile((std::istreambuf_iterator<char>(tempInputFile)),
								 std::istreambuf_iterator<char>());

		//Check signature with encrypted data, public key and signature in vote
		authentic = verifySignature(mypublicKey, dataTempFile, charSignature);

		if (authentic && valid)
		{
			std::cout << "Authentic" << std::endl;
			//first vote
			if (voters[stoi(voterID)] == 0)
			{
				voters[stoi(voterID)] = j + 1;
				lastTimestamps[stoi(voterID)] = timestamp;
			}
			else
			{
				//compare timestmaps
				if (compareTimestamps(timestamp, lastTimestamps[stoi(voterID)]))
				{
					voters[stoi(voterID)] = j + 1;
				}
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
	Plaintext accumulator_plain(to_string(0));
	//Encrypt plain text
	Ciphertext accumulator;
	encryptor.encrypt(accumulator_plain, accumulator);
	int actualVoters = NUMBERVOTERS;

	for (int k = 0; k < NUMBERVOTERS; k++)
	{
		lastVote = voters[k];
		//If voter did not vote skip
		if (lastVote == 0){ 
			actualVoters -= 1;
			continue;		
		}
	
		voteFileName = "Ballot/vote" + to_string(lastVote) + ".txt";
		cout << "Opening for checksum : " << voteFileName << endl;
		std::ifstream voteFile(voteFileName);
		std::string vote((std::istreambuf_iterator<char>(voteFile)),
						 std::istreambuf_iterator<char>());
		//Read vote get encrypted files and add them to checksum
		//Cycle through each vote cyphertexts
		istringstream ss(vote);
		do
		{
			// Read a word
			string word;
			ss >> word;

			//Compute add the encrypted value of the vote to the accumulator
			if (hasEnding(word, ".txt\""))
			{
				int id, hour, minute, second;

				voterWeightFileName = "Tally/encryptedWeight_" + to_string(k);
				//Load encrypted weight
				voterWeightFile.open(voterWeightFileName);
				voterWeights[k].load(context, voterWeightFile);
				voterWeightFile.close();

				Ciphertext multiply_result;
				ifstream voteEncryptedFile;
				//delete the " " from the begining and end
				word.erase(word.begin());
				word.erase(word.end() - 1);
				//add path to directorie
				word = "Ballot/" + word;
				//Load encrypted vote
				voteEncryptedFile.open(word);
				sscanf( word.c_str(), "Ballot/%d,%d,%d,%d.txt", &hour, &minute, &second, &id);
				// that will have all the votes of that candidate ( do a vector of ciphetext w/size of
				// number of candidates)
				Ciphertext encryptedVote;
				encryptedVote.load(context, voteEncryptedFile);
				evaluator.add_inplace(accumulator, encryptedVote);
				//multiply weight by encrypted vote and add to encrypted file
				evaluator.multiply(encryptedVote, voterWeights[k], multiply_result);
				evaluator.add_inplace(voteResults[id], multiply_result);
				voteEncryptedFile.close();
				continue;
			}
		} while (ss);
		voteFile.close();
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

	//Send number of actual voters to Counter
	ofstream actualVotersFile("Counter/actualVoters.txt");
	actualVotersFile << actualVoters;
	actualVotersFile.close();

	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

	/* Remove error strings */
	ERR_free_strings();

	return;
}

bool compareTimestamps(std::string timestamp, std::string lastTimestamp)
{
	bool recent = false;
	string hour1 = timestamp, hour2 = lastTimestamp, minute1 = timestamp, minute2 = lastTimestamp, second1 = timestamp, second2 = lastTimestamp;
	hour1.erase(2);
	hour2.erase(2);
	minute1.erase(5);
	minute1.erase(0, 3);
	minute2.erase(5);
	minute2.erase(0, 3);
	second1.erase(0, 6);
	second2.erase(0, 6);

	if (stoi(hour1) > stoi(hour2))
	{
		recent = true;
	}
	else if (stoi(minute1) > stoi(minute2))
	{
		recent = true;
	}
	else if (stoi(second1) > stoi(second2))
	{
		recent = true;
	}
	else
	{
		recent = false;
	}

	return recent;
}
