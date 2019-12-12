#include "resources.h"

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

//private key comes from openssl rsa -in client-cert0.key -check (need password)
//or better (cleans the file) comes from openssl rsa -in client-cert0.key -out newPrivateKey.key
//(need password)

std::string privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"
						 "MIICXQIBAAKBgQCmg00nu42DV1OMf8R+nb4z3pXDlLRf6/ZeOFu1mrRRmWMsNpHq\n"
						 "fl+OSUAFnJ8pDU5D229CxZzEmBmQEj6Cjs/9Rt6BM2f3Q5awCdUCDkogS/hPFB9u\n"
						 "CvgQgTfuxg8s+RdVKHNDqjQGw509RvtofCAyC8AdKUUh6t37xhTKkb1PWQIDAQAB\n"
						 "AoGAIDGctkTl3HIC3lRJqm1XO/IaJKFYqn8VuCvPV3Jc0LYGXaMDXUInuXviG/On\n"
						 "Nimzax0/CrroT35U2u0cFuQDxFVyw2vOlp1rMbDO4WdBgVZA4zunx2l6rL3/iTYx\n"
						 "7uUsDJPbDZPnsXn0m4hziP/PraxgRfUmgTSpnKcPUhXzuDECQQDcBVKc3uqceNvo\n"
						 "3Tby8bv6GHcitxauAI0IHgbSNa7cp5GGSXvMCXLQxDk8JUfReLtcwLWRFDnbCvIw\n"
						 "jV6u0rEdAkEAwb39lS531TRvK9idbHbyrerilE8gM7rBv0huRYelXVTrLIE7wbGm\n"
						 "zkHc2JvfGVDccrYPDb8cz2DmnkcXFhiebQJAKrvZ7OAbH2MWC2eT+aHcCdpgoVyA\n"
						 "SjGPMulqF8AXg4IEcNmq8tlO9J94Imd3SIczlPNVEKWmCxZYLff3UOtZPQJBALYQ\n"
						 "p8PQdjY6XxqSJmXuZeIAMEr1DKrwHvB1zYKzlTfe/F3HWHOOUdXUWQiJeh9dOLzn\n"
						 "z7+4UAel5TLqVYyjOAUCQQCNTH5B2kox64XkRc7X57gs8KqbiZ+yUU2dbPLZcq7i\n"
						 "GkEmBHumFd3Nsv1oVadeE6FLHxSHLMoAD9c1v4YlKlZj\n"
						 "-----END RSA PRIVATE KEY-----\n\0";

//public key comes from openssl x509 -pubkey -noout -in client-cert0.crt

std::string publicKey = "-----BEGIN PUBLIC KEY-----\n"
						"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmg00nu42DV1OMf8R+nb4z3pXD\n"
						"lLRf6/ZeOFu1mrRRmWMsNpHqfl+OSUAFnJ8pDU5D229CxZzEmBmQEj6Cjs/9Rt6B\n"
						"M2f3Q5awCdUCDkogS/hPFB9uCvgQgTfuxg8s+RdVKHNDqjQGw509RvtofCAyC8Ad\n"
						"KUUh6t37xhTKkb1PWQIDAQAB\n"
						"-----END PUBLIC KEY-----\n";

void voter(int NUMBERCANDIDATES, int NUMBERVOTERS, int NUMBERTRUSTEES)
{
	cout << "Voter App" << endl;

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

	string line;

	cout << "Insira o seu numero de votante:" << endl;
	cin >> myId;

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

	string filename = "Voter/Voter" + to_string(myId) + "/clientPublicKey" + to_string(myId) + ".key";
	//Fetch private and public keys of voter in order to sign
	std::ifstream publicKeyFile(filename);
	std::string mypublicKey((std::istreambuf_iterator<char>(publicKeyFile)),
							std::istreambuf_iterator<char>());

	cout << mypublicKey;
	filename = "Voter/Voter" + to_string(myId) + "/clientPrivateKey" + to_string(myId) + ".key";

	std::ifstream privateKeyFile(filename);
	std::string myprivateKey((std::istreambuf_iterator<char>(privateKeyFile)),
							 std::istreambuf_iterator<char>());

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
		return;
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
		return;
	}

	//ficheiro de voto
	filename = "Voter/vote" + to_string(myVote) + ".txt";
	ofstream votesFile(filename);
	votesFile << to_string(myId) << " " << to_string(hour) << "," << to_string(minute) << "," << to_string(second) << " ";

	int vote;
	int candidate = 1;
	ofstream tempSignFile("signatureTemp.txt");
	string timestamp = to_string(hour) + "," + to_string(minute) + "," + to_string(second);

	while (candidate >= 0)
	{
		cout << endl
			 << "Insira ID do candidato (-1 para sair)" << endl;
		cin >> candidate;

		if (candidate < 0)
		{
			cout << endl
				 << "You decided to exit vote app" << endl;
			break;
		}

		cout << "Insira o número de votos:" << endl;
		cin >> vote;

		//ficheiro de voto por candidato
		filename = to_string(hour) + "," + to_string(minute) + "," + to_string(second) + "," + to_string(candidate) + ".txt";

		//check if file already exists (trying to vote twice on the same candidate)
		ifstream fcheck(filename);
		bool newCandidate = true;
		if (fcheck.good())
		{
			cout << endl
				 << "You already voted on this candidate" << endl;
			newCandidate = false;
		}
		else
		{
			cout << endl
				 << "Voting in a new candidate" << endl;
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

		if (newCandidate)
		{
			votesFile << '"' << filename << '"' << " ";
			sprintf(command, "mv %s Ballot/", filename.c_str());
			system(command);
		}
	}

	//add Timestamp to signature file
	tempSignFile << timestamp;

	//Make signature from tempFile
	std::ifstream tempFile("signatureTemp.txt");
	std::string dataTempFile((std::istreambuf_iterator<char>(tempFile)),
							 std::istreambuf_iterator<char>());

	getchar();
	char *signature = signMessage(myprivateKey, dataTempFile);
	votesFile << ' ' << signature;
	votesFile.close();

	filename = "Voter/vote" + to_string(myVote) + ".txt";

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

	return;
}
