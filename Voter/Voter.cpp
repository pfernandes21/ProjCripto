#include "../resources.h"

#include <string>
#include <iostream>
#include <fstream>
#include <ctime>

using namespace std;
using namespace seal;


int main()
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

	/* ... Do some crypto stuff here ... */

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
	ifstream IdFileIn("id.txt", ios::in);
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
	ofstream IdFileOut("id.txt", ios::out);
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
	filename = "vote" + to_string(myVote) + ".txt";
	ofstream votesFile(filename);
	votesFile << to_string(myId) << " " << to_string(hour) << "," << to_string(minute) << "," << to_string(second) << " ";

	int vote;
	int candidate = 1;
	ofstream tempSignFile("signatureTemp.txt");

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
		
		//ficheiro de voto por candidato
		filename = to_string(hour) + "," + to_string(minute) + "," + to_string(second) + "," + to_string(candidate) + ".txt";

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
			sprintf(command, "mv Voter/%s Ballot/", filename.c_str());
			system(command);
		}
	}
	
	//Make signature from tempFile
	std::ifstream tempFile("signatureTemp.txt");
	std::string dataTempFile((std::istreambuf_iterator<char>(tempFile)),
    std::istreambuf_iterator<char>());
  	char* signature = signMessage(myprivateKey, dataTempFile);
	votesFile << ' ' << signature;

  	/* Clean up */
	filename = "vote" + to_string(myVote) + ".txt";
	votesFile.close();
	tempSignFile.close();
	sprintf(command, "mv Voter/%s Ballot/", filename.c_str());
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
