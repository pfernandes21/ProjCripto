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

int main()
{
    /* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

    int myId = 0, myVote = 0;

	string line;

	cout << "Insira o seu numero de votante:" << endl;
	cin >> myId;

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

    string filename;

    filename = "Voter/Voter" + to_string(myId) + "/clientPrivateKey" + to_string(myId) + ".key";
    std::ifstream privateKeyFile(filename);
	std::string myprivateKey((std::istreambuf_iterator<char>(privateKeyFile)),
							 std::istreambuf_iterator<char>());

	cout << myprivateKey;

    //Make signature from tempFile
	std::ifstream tempFile("signatureTemp.txt");
	std::string dataTempFile((std::istreambuf_iterator<char>(tempFile)),
							 std::istreambuf_iterator<char>());

    filename = "Voter/vote" + to_string(myVote) + ".txt";
	ofstream votesFile(filename);

    char *signature = signMessage(myprivateKey, dataTempFile);
	votesFile << ' ' << signature;
	votesFile.close();

	filename = "Voter/vote" + to_string(myVote) + ".txt";

    char command[50];
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