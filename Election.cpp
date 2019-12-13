// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "resources.h"

using namespace std;
using namespace seal;

int main(int argc, char *argv[])
{
  if (argc != 4)
  {
    printf("Insert all parameters (NCandidates, NVoters, NTrustees");
    exit(0);
  }

  int n_candidates = 0, n_voters = 0, n_trustees = 0;
  n_candidates = stoi(argv[1]);
  n_voters = stoi(argv[2]);
  n_trustees = stoi(argv[3]);

  if (!(n_candidates > 0 && n_voters > 0 && n_trustees > 0))
  {
    printf("Insert correct parameters");
    exit(0);
  }

#ifdef SEAL_VERSION
  cout << "Microsoft SEAL version: " << SEAL_VERSION << endl;
#endif
  while (true)
  {
    cout << "+---------------------------------------------------------+" << endl;
    cout << "| Role                       | Source Files               |" << endl;
    cout << "+----------------------------+----------------------------+" << endl;
    cout << "| 1. Admin                   | Admin.cpp                  |" << endl;
    cout << "| 2. Voter                   | Voter.cpp                  |" << endl;
    cout << "| 3. Tally                   | Tally.cpp                  |" << endl;
    cout << "| 4. Counter                 | Counter.cpp                |" << endl;
    cout << "+----------------------------+----------------------------+" << endl;

    /*
        Print how much memory we have allocated from the current memory pool.
        By default the memory pool will be a static global pool and the
        MemoryManager class can be used to change it. Most users should have
        little or no reason to touch the memory allocation system.
        */
    size_t megabytes = MemoryManager::GetPool().alloc_byte_count() >> 20;
    cout << "[" << setw(7) << right << megabytes << " MB] "
         << "Total allocation from the memory pool" << endl;

    int selection = 0;
    bool invalid = true;

    do
    {
      cout << endl
           << "> Run example (1 ~ 4) or exit (0): ";
      if (!(cin >> selection))
      {
        invalid = false;
      }
      else if (selection < 0 || selection > 4)
      {
        invalid = false;
      }
      else
      {
        invalid = true;
      }
      if (!invalid)
      {
        cout << "  [Beep~~] Invalid option: type 0 ~ 4" << endl;
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
      }
    } while (!invalid);

    switch (selection)
    {
    case 1:
      admin(n_candidates, n_voters, n_trustees);
      break;

    case 2:
      voter(n_candidates, n_voters, n_trustees);
      break;

    case 3:
      tally(n_candidates, n_voters, n_trustees);
      break;

    case 4:
      counter(n_candidates, n_voters, n_trustees);
      break;

    case 0:
      system("./exit.sh");
      return 0;
    }
  }

  return 0;
}

RSA *createPrivateRSA(std::string key)
{
  RSA *rsa = NULL;
  const char *c_string = key.c_str();
  BIO *keybio = BIO_new_mem_buf((void *)c_string, -1);
  if (keybio == NULL)
  {
    return 0;
  }
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
  return rsa;
}

RSA *createPublicRSA(std::string key)
{
  RSA *rsa = NULL;
  BIO *keybio;
  const char *c_string = key.c_str();
  keybio = BIO_new_mem_buf((void *)c_string, -1);
  if (keybio == NULL)
  {
    return 0;
  }
  rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
  return rsa;
}

bool RSASign(RSA *rsa,
             const unsigned char *Msg,
             size_t MsgLen,
             unsigned char **EncMsg,
             size_t *MsgLenEnc)
{
  EVP_MD_CTX *m_RSASignCtx = EVP_MD_CTX_new();
  EVP_PKEY *priKey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0)
  {
    return false;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0)
  {
    return false;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0)
  {
    return false;
  }
  *EncMsg = (unsigned char *)malloc(*MsgLenEnc);
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0)
  {
    return false;
  }
  EVP_MD_CTX_free(m_RSASignCtx);
  return true;
}

bool RSAVerifySignature(RSA *rsa,
                        unsigned char *MsgHash,
                        size_t MsgHashLen,
                        const char *Msg,
                        size_t MsgLen,
                        bool *Authentic)
{
  *Authentic = false;
  EVP_PKEY *pubKey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX *m_RSAVerifyCtx = EVP_MD_CTX_new();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
  {
    return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0)
  {
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus == 1)
  {
    *Authentic = true;
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return true;
  }
  else if (AuthStatus == 0)
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

void Base64Encode(const unsigned char *buffer,
                  size_t length,
                  char **base64Text)
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

  *base64Text = (*bufferPtr).data;
}

size_t calcDecodeLength(const char *b64input)
{
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len - 1] == '=') //last char is =
    padding = 1;
  return (len * 3) / 4 - padding;
}

void Base64Decode(const char *b64message, unsigned char **buffer, size_t *length)
{
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char *)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

char *signMessage(std::string privateKey, std::string plainText)
{
  RSA *privateRSA = createPrivateRSA(privateKey);
  unsigned char *encMessage;
  char *base64Text;
  size_t encMessageLength;
  RSASign(privateRSA, (unsigned char *)plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
  Base64Encode(encMessage, encMessageLength, &base64Text);
  free(encMessage);
  return base64Text;
}

bool verifySignature(std::string publicKey, std::string plainText, char *signatureBase64)
{
  RSA *publicRSA = createPublicRSA(publicKey);
  unsigned char *encMessage;
  size_t encMessageLength;
  bool authentic;
  Base64Decode(signatureBase64, &encMessage, &encMessageLength);
  bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
  return result & authentic;
}

bool simpleSHA256(void *input, unsigned long length, unsigned char *md)
{
  SHA256_CTX context;
  if (!SHA256_Init(&context))
    return false;

  if (!SHA256_Update(&context, (unsigned char *)input, length))
    return false;

  if (!SHA256_Final(md, &context))
    return false;

  return true;
}