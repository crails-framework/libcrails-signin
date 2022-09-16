#include "password.hpp"
#include <crails/utils/base64.hpp>
#include <crails/cipher.hpp>
#include <openssl/md5.h>

using namespace std;
using namespace Crails;

string Password::md5(const string& str)
{
  unsigned char result[MD5_DIGEST_LENGTH];

  MD5((const unsigned char*)str.c_str(), str.size(), result);
  return (base64_encode(result, MD5_DIGEST_LENGTH));
}

string Password::aes(const string& str)
{
  Cipher cipher;

  return cipher.encrypt(str, encrypt_key, encrypt_salt);
}
