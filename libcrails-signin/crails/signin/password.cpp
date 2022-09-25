#include "password.hpp"
#include <crails/utils/base64.hpp>
#include <crails/cipher.hpp>
#include <crails/md5.hpp>

using namespace std;
using namespace Crails;

string Password::md5(const string& str)
{
  Md5Digest digest;

  digest << str << encrypt_key << encrypt_salt;
  return digest.to_string();
}

string Password::aes(const string& str)
{
  Cipher cipher;

  return cipher.encrypt(str, encrypt_key, encrypt_salt);
}
