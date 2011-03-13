#ifndef AES_H
#define AES_H

#include <string>
#include <sstream>

namespace FAES {
  namespace AES {
    enum Mode {
      // Counter-Block Chaining.
      CBC,

      // Counter.
      CTR,

      // Electronic CodeBook.
      ECB
    };

    enum KeySize {
      _128_BITS = 16, // bytes
      _192_BITS = 24,
      _256_BITS = 32
    };

    class Key {
    public:
      Key(KeySize size) : iv(NULL), nonce(NULL), size(size) {
        key = new unsigned char[size];
      }

      ~Key() {
        delete[] key;
        delete[] iv;
        delete[] nonce;
      }

      std::string toString() const;

      // iv and nonce should be terminated with a \0.
      unsigned char *key, *iv, *nonce;
      KeySize size;
    };

    std::ostream &operator<<(std::ostream &os, const Key &key);

    class Cryptor {
    public:
      Cryptor(Mode mode);
      ~Cryptor();

      Mode getMode() const { return mode; }

      Key genKey(KeySize size);

      void encrypt(const std::string &plaintext, const Key &key,
                   std::string *ciphertext);
      void decrypt(const std::string &ciphertext, const Key &key,
                   std::string *plaintext);    

    private:
      void genKeySchedule(const Key &key,
                          unsigned char **schedule);

      void expandKey128(const unsigned char *key,
                        unsigned char *schedule);
      void expandKey192(const unsigned char *key,
                        unsigned char *schedule);
      void expandKey256(const unsigned char *key,
                        unsigned char *schedule);            

      void ecbEncrypt(const std::string &plaintext, const Key &key,
                      std::string *ciphertext,
                      unsigned char *schedule);
      void ecbDecrypt(const std::string &ciphertext, const Key &key,
                      std::string *plaintext,
                      unsigned char *schedule);      
    
      Mode mode;
    };
  }
}

#endif // AES_H
