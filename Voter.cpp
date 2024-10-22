#include "resources.h"

using namespace std;
using namespace seal;

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
	ifstream privateKeyFile1;
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

	if(myId < 0 || myId >= NUMBERVOTERS)
	{
		cout << "Invalid ID" << endl;
		return;
	}

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
	publicKeyFile.close();

	filename = "Voter/Voter" + to_string(myId) + "/clientPrivateKey" + to_string(myId) + ".key";

	std::ifstream privateKeyFile(filename);
	std::string myprivateKey((std::istreambuf_iterator<char>(privateKeyFile)),
							 std::istreambuf_iterator<char>());
	privateKeyFile.close();

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
	int candidates_voted[NUMBERCANDIDATES] = {0};
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

		if(vote < 0)
		{
			cout << "Vote must be bigger than 0" << endl;
			continue;
		}

		//ficheiro de voto por candidato
		filename = to_string(hour) + "," + to_string(minute) + "," + to_string(second) + "," + to_string(candidate) + ".txt";

		//check if file already exists (trying to vote twice on the same candidate)
		ifstream fcheck("Ballot/" + filename);
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

		if (newCandidate)
		{
			ofstream candidateVoteFile(filename);
			Plaintext voteValue;
			Ciphertext encryptedVote;

			//encrypt and store vote
			voteValue = encoder.encode(vote);
			encryptor.encrypt(voteValue, encryptedVote);
			encryptedVote.save(candidateVoteFile);
			encryptedVote.save(tempSignFile);
			candidateVoteFile.close();

			if(candidate < NUMBERCANDIDATES) candidates_voted[candidate] = 1;
			votesFile << '"' << filename << '"' << " ";
			sprintf(command, "mv %s Ballot/", filename.c_str());
			system(command);
		}
	}

	for(int i=0;i<NUMBERCANDIDATES;i++)
	{
		if(candidates_voted[i] == 0)
		{
			vote = 0;
		}
		else continue;

		//ficheiro de voto por candidato
		filename = to_string(hour) + "," + to_string(minute) + "," + to_string(second) + "," + to_string(i) + ".txt";

		ofstream candidateVoteFile(filename);
		Plaintext voteValue;
		Ciphertext encryptedVote;

		//encrypt and store vote
		voteValue = encoder.encode(vote);
		encryptor.encrypt(voteValue, encryptedVote);
		encryptedVote.save(candidateVoteFile);
		encryptedVote.save(tempSignFile);
		candidateVoteFile.close();

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
	tempFile.close();

	char *signature = signMessage(myprivateKey, dataTempFile);
	votesFile << ' ' << signature;
	votesFile.close();

	tempSignFile.close();

	filename = "Voter/vote" + to_string(myVote) + ".txt";
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
