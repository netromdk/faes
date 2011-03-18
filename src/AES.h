#ifndef AES_H
#define AES_H

#include <string>
#include <sstream>
#include <emmintrin.h>

#include "Common.h"
#include "Key.h"
#include "KeySize.h"

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

      void cbcEncrypt(const std::string &plaintext, const Key &key,
                      std::string *ciphertext,
                      unsigned char *schedule);
      void cbcDecrypt(const std::string &ciphertext, const Key &key,
                      std::string *plaintext,
                      unsigned char *schedule);            
    
      Mode mode;
      bool bigEndian;
    };
  }
}

#endif // AES_H
