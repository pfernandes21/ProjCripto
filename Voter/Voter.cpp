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

int main()
{	
	cout << "Voter App" << endl;

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
	electionPublicKeyFile.open("Voter/publicKey.txt");
	cout << "Load public key" << endl;
	public_key.load(context, electionPublicKeyFile);
	Encryptor encryptor(context, public_key);
	electionPublicKeyFile.close();

	//timestamp
	int hour = (time(0) / 3600) % 24;
	int minute = (time(0) % 3600) / 60;
	int second = (time(0) % 60);

	//Command for command line
	char command[300];

	//id do votante e id do voto
	int myId = 0, myVote = 0;

	cout << "Insira o seu numero de votante:" << endl;
	cin >> myId;

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

	//Fetch private and public keys of voter in order to sign
	string filename = "Voter/Voter" + to_string(myId) + "/clientPublicKey" + to_string(myId) + ".key" ;
	std::ifstream publicKeyFile(filename);
	std::string mypublicKey((std::istreambuf_iterator<char>(publicKeyFile)), std::istreambuf_iterator<char>());
	cout << mypublicKey;

	filename = "Voter/Voter" + to_string(myId) + "/clientPrivateKey" + to_string(myId) + ".key";
	std::ifstream privateKeyFile(filename);
	std::string myprivateKey((std::istreambuf_iterator<char>(privateKeyFile)), std::istreambuf_iterator<char>());
	cout << myprivateKey;

	//get id do voto no ficheiro
	ifstream IdFileIn("Voter/id.txt", ios::in);
	if (IdFileIn.is_open())
	{
		while (getline(IdFileIn, line))
		{
			myVote = stoi(line);
		}
		IdFileIn.close();
	}
	else
	{
		return 0;
	}

	//update id do voto no ficheiro
	myVote++;
	ofstream IdFileOut("Voter/id.txt", ios::out);
	if (IdFileOut.is_open())
	{
		IdFileOut << to_string(myVote) << endl;
		IdFileOut.close();
	}
	else
	{
		return 0;
	}

	//ficheiro de voto
	filename = "Voter/vote" + to_string(myVote) + ".txt";
	ofstream votesFile(filename);
	votesFile << to_string(myId) << " " << to_string(hour) << "," << to_string(minute) << "," << to_string(second) << " ";

	int vote;
	int candidate = 1;
	int *candidates = new int[NUMBERCANDIDATES];
	ofstream tempSignFile("signatureTemp.txt");
	string timestamp = to_string(hour) + "," + to_string(minute) + "," + to_string(second);

	while (candidate >= 0)
	{
		cout << endl << "Insira ID do candidato (-1 para sair)" << endl;
		cin >> candidate;

		if (candidate < 0)
		{
			cout << endl << "You decided to exit vote app"<< endl;
			break;
		}

		cout << "Insira o número de votos:" << endl;
		cin >> vote;
		
		candidates[candidate] = 1;

		//ficheiro de voto por candidato
		filename = "Voter/" + to_string(hour) + "," + to_string(minute) + "," + to_string(second) + "," + to_string(candidate) + ".txt";

		//check if file already exists (trying to vote twice on the same candidate)
		ifstream fcheck(filename);
		bool newCandidate = true;
		if(fcheck.good())
		{
			cout << endl << "You already voted on this candidate"<< endl;
			newCandidate =false;
		} 
		else 
		{
			cout << endl << "Voting in a new candidate"<< endl;
			newCandidate = true;
		}
		fcheck.close();
		
		ofstream candidateVoteFile(filename);
		Plaintext voteValue;
		Ciphertext encryptedVote;

		if (candidateVoteFile.is_open())
		{	
			//encrypt and store vote
			voteValue = encoder.encode(vote);	
			encryptor.encrypt(voteValue, encryptedVote);
			encryptedVote.save(candidateVoteFile);
			encryptedVote.save(tempSignFile);
			candidateVoteFile.close();
		}

		if(newCandidate)
		{
			votesFile << '"' << filename << '"' << " ";	
			sprintf(command, "mv %s Ballot/", filename.c_str());
			system(command);
		}
	}

	for(int i = 0; i < NUMBERCANDIDATES; i++)
	{
		if(candidates[i] == 1)
		{
			continue;
		}
		else
		{
			vote = 0;
		}
		
		//ficheiro de voto por candidato
		filename = "Voter/" + to_string(hour) + "," + to_string(minute) + "," + to_string(second) + "," + to_string(i) + ".txt";
		ofstream candidateVoteFile(filename);
		Plaintext voteValue;
		Ciphertext encryptedVote;

		if (candidateVoteFile.is_open())
		{	
			//encrypt and store vote
			voteValue = encoder.encode(vote);	
			encryptor.encrypt(voteValue, encryptedVote);
			encryptedVote.save(candidateVoteFile);
			encryptedVote.save(tempSignFile);
			candidateVoteFile.close();
		}

		votesFile << '"' << filename << '"' << " ";	
		sprintf(command, "mv %s Ballot/", filename.c_str());
		system(command);
	}
	
	//add Timestamp to signature file
	tempSignFile << timestamp;

	//Make signature from tempFile
	std::ifstream tempFile("signatureTemp.txt");
	std::string dataTempFile((std::istreambuf_iterator<char>(tempFile)),
    std::istreambuf_iterator<char>());
  	char* signature = signMessage(myprivateKey, dataTempFile);
	votesFile << ' ' << signature;

  	/* Clean up */
	filename = "Voter/vote" + to_string(myVote) + ".txt";
	votesFile.close();
	tempSignFile.close();
	sprintf(command, "mv %s Ballot/", filename.c_str());
	system(command);
	system("rm signatureTemp.txt");

	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

	/* Remove error strings */
	ERR_free_strings();

	return 0;
}
