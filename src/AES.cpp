#include <cstring>
using namespace std;

#include "AES.h"
#include <wmmintrin.h>

namespace FAES {
  namespace AES {
    string Key::toString() const {
      stringstream ss;
      ss << "Key { size:  " << size << endl
         << "      key:   ";

      for (int i = 0; i < size; i++) {
        ss << key[i];
      }

      if (iv) {
        ss << endl << "      iv:    " << iv;
      }

      if (nonce) {
        ss << endl << "      nonce: " << nonce;
      }      
      
      ss << " }";
      return ss.str();
    }
    
    ostream &operator<<(ostream &os, const Key &key) {
      os << key.toString();
      return os;
    }  
    
    Cryptor::Cryptor(Mode mode) : mode(mode) { }

    Cryptor::~Cryptor() { }

    Key Cryptor::genKey(KeySize size) {
      Key key(size);
      memset(key.key, 81, size);

      if (mode == CBC) {
        key.iv = new unsigned char[17];
        memset(key.iv, 82, 16);
        key.iv[16] = '\0';
      }
      else if (mode == CTR) {
        key.iv = new unsigned char[13];
        memset(key.iv, 82, 12);
        key.iv[12] = '\0';      
      
        key.nonce = new unsigned char[5];
        memset(key.nonce, 83, 4);
        key.nonce[4] = '\0';
      }
    
      return key;
    }

    void Cryptor::encrypt(const string &plaintext, const Key &key,
                          string *ciphertext) {
      unsigned char *schedule;
      genKeySchedule(key, &schedule);
      
      switch (mode) {
      case ECB:
        ecbEncrypt(plaintext, key, ciphertext, schedule);
        break;

      case CBC:
        break;

      case CTR:
        break;        
      }

      delete[] schedule;
    }

    void Cryptor::decrypt(const string &ciphertext, const Key &key,
                          string *plaintext) {
      unsigned char *schedule;
      genKeySchedule(key, &schedule);
      
      switch (mode) {
      case ECB:
        ecbDecrypt(ciphertext, key, plaintext, schedule);
        break;

      case CBC:
        break;

      case CTR:
        break;         
      }

      delete[] schedule;
    }

    void Cryptor::genKeySchedule(const Key &key,
                                 unsigned char **schedule) {
      switch (key.size) {
      case _128_BITS:
        *schedule = new unsigned char[11 * 16];
        expandKey128(key.key, schedule[0]);
        break;

      case _192_BITS:
        *schedule = new unsigned char[14 * 16];
        expandKey192(key.key, schedule[0]);        
        break;

      case _256_BITS:
        *schedule = new unsigned char[15 * 16];
        expandKey256(key.key, schedule[0]);        
        break;         
      }      
    }

    void Cryptor::expandKey128(const unsigned char *key,
                               unsigned char *schedule) {
      __m128i *keySchedule = (__m128i*) schedule;

      // The first entry is just the key itself.
      __m128i tmp = _mm_loadu_si128((__m128i*) key);
      keySchedule[0] = tmp;

      
    }
    
    void Cryptor::expandKey192(const unsigned char *key,
                               unsigned char *schedule) {

    }

    void Cryptor::expandKey256(const unsigned char *key,
                               unsigned char *schedule) {
      
    }

    void Cryptor::ecbEncrypt(const string &plaintext, const Key &key,
                             string *ciphertext,
                             unsigned char *schedule) {
      
    }
    
    void Cryptor::ecbDecrypt(const string &ciphertext, const Key &key,
                             string *plaintext,
                             unsigned char *schedule) {
      
    }
  }
}
