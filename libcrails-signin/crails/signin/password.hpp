#ifndef  CRAILS_PASSWORD_HPP
# define CRAILS_PASSWORD_HPP

# include <string>

namespace Crails
{
  struct Password : public std::string
  {
    Password(void)
    {
    }

    Password(const Password& str) : std::string(str.c_str())
    {
    }
    
    Password(const std::string& str) : std::string(encrypt(str))
    {
    }
    
    Password(const char* str) : std::string(encrypt(str))
    {
    }
    
    Password& operator=(const std::string& str)
    {
      std::string::operator=(encrypt(str));
      return (*this);
    }

    Password& operator=(const Password& str)
    {
      std::string::operator=(str.c_str());
      return (*this);
    }

    bool      operator==(const Password& str) const
    {
      return std::string(str.c_str()) == c_str();
    }

    bool      operator==(const std::string& str) const
    {
      return (encrypt(str) == c_str());
    }
    
    bool      operator==(const char* str) const
    {
      return (encrypt(str) == c_str());
    }
    
    virtual std::string encrypt(const std::string& str) const { return aes(str); }

  protected:
    static std::string md5(const std::string& str);
    static std::string aes(const std::string& str);

    static const std::string encrypt_key;
    static const std::string encrypt_salt;
  };
}

#endif
