#ifndef AES_H
#define AES_H

#include <string>
#include <sstream>
#include <emmintrin.h>

#include "Common.h"

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
      ALIGN16 unsigned char *key, *iv, *nonce;
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
      static int getRounds(const KeySize &size);
      
      unsigned char *genKeySchedule(const Key &key,
                                    bool encryption = true);

      __m128i assistKey128(__m128i tmp, __m128i tmp2);
      void expandKey128(const unsigned char *key,
                        unsigned char *schedule);

      void assistKey192(__m128i *tmp, __m128i *tmp2,
                           __m128i *tmp3);
      void expandKey192(const unsigned char *key,
                        unsigned char *schedule);

      void assistKey256_1(__m128i *tmp, __m128i *tmp2); 
      void assistKey256_2(__m128i *tmp, __m128i *tmp2); 
      void expandKey256(const unsigned char *key,
                        unsigned char *schedule);            

      void ecbEncrypt(const std::string &plaintext, const Key &key,
                      std::string *ciphertext,
                      unsigned char *schedule);
      void ecbDecrypt(const std::string &ciphertext, const Key &key,
                      std::string *plaintext,
                      unsigned char *schedule);      
    
      Mode mode;
      bool bigEndian;
    };
  }
}

#endif // AES_H
