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

void signer(int NUMBERCANDIDATES, int NUMBERVOTERS, int NUMBERTRUSTEES)
{
    /* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

    filename = "Voter/Voter" + to_string(myId) + "/clientPrivateKey" + to_string(myId) + ".key";
    std::ifstream privateKeyFile(filename);
	std::string myprivateKey((std::istreambuf_iterator<char>(privateKeyFile)),
							 std::istreambuf_iterator<char>());

	cout << myprivateKey;

    //Make signature from tempFile
	std::ifstream tempFile("signatureTemp.txt");
	std::string dataTempFile((std::istreambuf_iterator<char>(tempFile)),
							 std::istreambuf_iterator<char>());

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

}