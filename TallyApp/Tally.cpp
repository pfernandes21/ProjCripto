#include "../resources.h"
#include "../criptlib.h"

#include <string>
#include <iostream>
#include <fstream>
#include <ctime>

using namespace std;
using namespace seal;


bool hasEnding (std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}

void tallyApp()
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
	electionPublicKeyFile.open("Administrator/electionKeys/publicKey.txt");
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

  /* ... Do some crypto stuff here ... */

	
	//Fetch  public key of voter in order to check signature
	std::ifstream publicKeyFile("client0/clientPublicKey0.key");
	std::string mypublicKey((std::istreambuf_iterator<char>(publicKeyFile)),
                 std::istreambuf_iterator<char>());


	//Fetch vote 
	std::ifstream voteFile("Ballot/vote30.txt");
	std::string vote((std::istreambuf_iterator<char>(voteFile)),
                 std::istreambuf_iterator<char>());
	
	string signature;

	std::ofstream tempFile("signatureTemp.txt");
	std::ifstream voteEncryptedFile;
	bool signatureCheck = false;

    //Reade vote, and when reading files of encrypted votes open them
    // then add them in a file for later signature check
    istringstream ss(vote); 
    do { 
        // Read a word 
        string word; 
        ss >> word; 
 
	if(hasEnding(word, ".txt\"")){
		//delete the " " from the begining and end
		word.erase(word.begin());
		word.erase(word.end()-1);
		//add path to directorie
		word = "Ballot/"+word;
		//OpenEncrypted vote file and copy its data to tempFile
		voteEncryptedFile.open(word);
		std::string dataEncrypted((std::istreambuf_iterator<char>(voteEncryptedFile)),
				std::istreambuf_iterator<char>());
		tempFile << dataEncrypted;
		
		//this is to guarantee that it fetches only the signature check after
		signatureCheck = true;
		continue;
  	}

	if(signatureCheck){
		cout << word;
        	signature = signature + word ;
		signature = signature + '\n'; 
   	}
    } while (ss); 

	tempFile.close();

	//Grab tempFile created to
	std::ifstream tempInputFile("signatureTemp.txt");
	//Convert string to char*
	// declaring character array : p 
   	char charSignature[signature.length()]; 
  
   	int i; 
    	for (i = 0; i < signature.length()+1; i++) { 
        	charSignature[i] = signature[i];
   	 }


	//Fetch data from temporary file
	std::string dataTempFile((std::istreambuf_iterator<char>(tempInputFile)),
                 std::istreambuf_iterator<char>());	

	//Check signature with encrypted data, public key and signature in vote
	bool authentic = verifySignature(mypublicKey, dataTempFile, charSignature);
	  if ( authentic ) {
	    std::cout << "Authentic" << std::endl;
	  } else {
	    std::cout << "Not Authentic" << std::endl;
	  }
	
  /* Clean up */

	tempFile.close();

  /* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();

	return;
}
