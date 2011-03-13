#include <cstring>
#include <wmmintrin.h>
using namespace std;

#include "AES.h"
#include "Common.h"

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

    inline __m128i Cryptor::assistKey128(__m128i tmp, __m128i tmp2) {
      // Shift 4 bytes to the left (zero-padding) and xor tmp with it.
      __m128i tmp3 = _mm_slli_si128(tmp, 0x4);
      tmp = _mm_xor_si128(tmp, tmp3);
      
      tmp3 = _mm_slli_si128(tmp3, 0x4);
      tmp = _mm_xor_si128(tmp, tmp3);
      
      tmp3 = _mm_slli_si128(tmp3, 0x4);
      tmp = _mm_xor_si128(tmp, tmp3);

      // Duplicate the 4th 32-bit part 4 times:
      // [1, 2, 3, 4] -> [4, 4, 4, 4]
      tmp2 = _mm_shuffle_epi32(tmp2, SHUFFLE4_32(3, 3, 3, 3));

      // Then xor tmp with tmp2.
      tmp = _mm_xor_si128(tmp, tmp2);
      return tmp;     
    }

    void Cryptor::expandKey128(const unsigned char *key,
                               unsigned char *schedule) {
      __m128i *keySchedule = (__m128i*) schedule;

      // The first entry is just the key itself.
      __m128i tmp = _mm_loadu_si128((__m128i*) key);
      keySchedule[0] = tmp;

      // The assist pretty much does the following:
      //   SubWord(RotWord(tmp)) xor RCON[i/Nk]
      __m128i tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[0]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[1] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[1]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[2] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[2]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[3] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[3]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[4] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[4]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[5] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[5]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[6] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[6]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[7] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[7]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[8] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[8]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[9] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, RCON[9]);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[10] = tmp;            
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
