#include "../resources.h"

#include <string>
#include <iostream>
#include <fstream>
#include <ctime>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <assert.h>

using namespace std;
using namespace seal;

RSA* createPrivateRSA(std::string key) 
{
    RSA *rsa = NULL;
    const char* c_string = key.c_str();
    BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio==NULL) 
    {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    return rsa;
}

RSA* createPublicRSA(std::string key) 
{
    RSA *rsa = NULL;
    BIO *keybio;
    const char* c_string = key.c_str();
    keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio==NULL) 
    {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    return rsa;
}

bool RSASign(RSA* rsa, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc) 
{
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_new();
    EVP_PKEY* priKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    if(EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) 
    {
        return false;
    }
    if(EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) 
    {
        return false;
    }
    if(EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) 
    {
        return false;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if(EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) 
    {
        return false;
    }
    EVP_MD_CTX_free(m_RSASignCtx);
    return true;
}

bool RSAVerifySignature(RSA* rsa, unsigned char* MsgHash, size_t MsgHashLen, const char* Msg, size_t MsgLen, bool* Authentic) 
{
    *Authentic = false;
    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_new();

    if(EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) 
    {
        return false;
    }
    if(EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) 
    {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if(AuthStatus==1) 
    {
        *Authentic = true;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    } 
    else if(AuthStatus==0)
    {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    } 
    else
    {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return false;
    }
}

void Base64Encode(const unsigned char* buffer, size_t length, char** base64Text) 
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *base64Text=(*bufferPtr).data;
}

size_t calcDecodeLength(const char* b64input) 
{
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
    return (len*3)/4 - padding;
}

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) 
{
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

char* signMessage(std::string privateKey, std::string plainText) 
{
    RSA* privateRSA = createPrivateRSA(privateKey); 
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;
    RSASign(privateRSA, (unsigned char*) plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    return base64Text;
}

bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) 
{
    RSA* publicRSA = createPublicRSA(publicKey);
    unsigned char* encMessage;
    size_t encMessageLength;
    bool authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
    return result & authentic;
}

bool compareTimestamps(std::string timestamp, std::string lastTimestamp){
	bool recent=false;
	string hour1=timestamp, hour2=lastTimestamp, minute1=timestamp, minute2=lastTimestamp, second1=timestamp, second2=lastTimestamp;
	hour1.erase(2);
	hour2.erase(2);
	minute1.erase(5);
	minute1.erase(0,3);
	minute2.erase(5);
	minute2.erase(0,3);
	second1.erase(0, 6);
	second2.erase(0, 6); 
	
	if(stoi(hour1) > stoi(hour2)){
		recent=true;
	}else if (stoi(minute1) > stoi(minute2)){
		recent=true;
	}else if(stoi(second1) > stoi(second2)){
		recent=true;
	} else {
		recent=false;
	}

	return recent;
}

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
	
	int NUMBERCANDIDATES, NUMBERVOTERS;
	string line;
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

	string lastTimestamps[NUMBERVOTERS] = {"0"};
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
	//Cicle for reading all votes in ballot
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

	bool firstWord;
	string timestamp;
	for (int j = 0; j < numberVotes; j++) 
	{
		voteFileName = "Ballot/vote" + to_string(j + 1) + ".txt";
		signature = "";
		signatureCheck = false;
		voterIDCheck = true;
		firstWord = true;
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

			//fetch timestamp
			if(firstWord) firstWord = false;

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
			if(signatureCheck)
			{
				signature = signature + word ;
				signature = signature + '\n';
				continue;
	   		}
			else if(voterIDCheck)
			{
				voterIDCheck = false;
				voterID = word;
				continue;
			}
			else if(!firstWord)
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
		std::string dataTempFile((std::istreambuf_iterator<char>(tempInputFile)), std::istreambuf_iterator<char>());
		//Check signature with encrypted data, public key and signature in vote
		authentic = verifySignature(mypublicKey, dataTempFile, charSignature);

		if ( authentic ) 
		{
			std::cout << "Authentic" << std::endl;
			//first vote
			if(voters[stoi(voterID)] == 0)
			{
				voters[stoi(voterID)] = j+1;
				lastTimestamps[stoi(voterID)] = timestamp;
			} 
			else
			{
				//compare timestmaps
				if(compareTimestamps(timestamp,lastTimestamps[stoi(voterID)]))
				{
					voters[stoi(voterID)] = j+1;
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
