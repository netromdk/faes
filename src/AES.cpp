#include <cstring>
#include <wmmintrin.h>
using namespace std;

#include "AES.h"

namespace FAES {
  namespace AES {
    string Key::toString() const {
      stringstream ss;
      ss << "Key { size:  " << (size * 8) << " bits" << endl
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
    
    Cryptor::Cryptor(Mode mode) : mode(mode) {
      // Determine endianness.
      bigEndian = isBigEndian();
    }

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
      ALIGN16 unsigned char *schedule = genKeySchedule(key);
      
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
      
      ALIGN16 unsigned char *schedule = genKeySchedule(key, false);
      
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

    inline int Cryptor::getRounds(const KeySize &size) {
      switch (size) {
      default:
      case _128_BITS:
        return 10;

      case _192_BITS:
        return 12;

      case _256_BITS:
        return 14;
      }
    }

    unsigned char *Cryptor::genKeySchedule(const Key &key,
                                                   bool encryption) {
      ALIGN16 unsigned char *schedule = new unsigned char[15 * 16];
      int upper;
      
      switch (key.size) {
      case _128_BITS:
        upper = 9;
        expandKey128(key.key, schedule);
        break;

      case _192_BITS:
        upper = 11;
        expandKey192(key.key, schedule);        
        break;

      case _256_BITS:
        upper = 13;
        expandKey256(key.key, schedule);        
        break;         
      }

      // Generate decryption round keys by using aesimc
      // instruction. This only concerns keys 1-9/11/13. And reverse
      // the order for all of them!
      if (!encryption) {
        __m128i *keySchedule = (__m128i*) schedule;

        ALIGN16 unsigned char *tempSchedule =
          new unsigned char[15 * 16];
        __m128i *tempKeySchedule = (__m128i*) tempSchedule;

        tempKeySchedule[upper + 1] = keySchedule[0];
        
        for (int i = 1; i <= upper; i++) {
          tempKeySchedule[(upper + 1) - i] =
            _mm_aesimc_si128(keySchedule[i]);
        }

        tempKeySchedule[0] = keySchedule[upper + 1];

        // Now use the temp. instead!
        delete[] schedule;
        return (unsigned char*) tempKeySchedule;
      }

      return schedule;
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
      if (!bigEndian) {
        reverse_m128i(tmp); // swap byte-order => big-endian.
      }
      keySchedule[0] = tmp;

      // Sadly, these cannot be done in a loop because the second
      // argument of _mm_aeskeygenassist_si128() needs to be a 8-bit
      // immediate!

      // The assist pretty much does the following:
      //   SubWord(RotWord(tmp)) xor RCON[round]
      __m128i tmp2 = _mm_aeskeygenassist_si128(tmp, 0x1);      
      tmp = assistKey128(tmp, tmp2);
      keySchedule[1] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x2);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[2] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x4);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[3] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x8);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[4] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x10);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[5] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x20);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[6] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x40);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[7] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x80);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[8] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x1B);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[9] = tmp;

      tmp2 = _mm_aeskeygenassist_si128(tmp, 0x36);
      tmp = assistKey128(tmp, tmp2);
      keySchedule[10] = tmp;            
    }

    inline void Cryptor::assistKey192(__m128i *tmp, __m128i *tmp2,
                                      __m128i *tmp3) {
      // Duplicate the 2nd 32-bit part 4 times:
      // [1, 2, 3, 4] -> [2, 2, 2, 2]      
      __m128i tmp4;
      *tmp2 = _mm_shuffle_epi32(*tmp2, SHUFFLE4_32(1, 1, 1, 1));
      
      tmp4 = _mm_slli_si128(*tmp, 0x4);
      *tmp = _mm_xor_si128(*tmp, tmp4);
      
      tmp4 = _mm_slli_si128(tmp4, 0x4);
      *tmp = _mm_xor_si128(*tmp, tmp4);
      
      tmp4 = _mm_slli_si128(tmp4, 0x4);
      *tmp = _mm_xor_si128(*tmp, tmp4);
      
      *tmp = _mm_xor_si128(*tmp, *tmp2);

      // Duplicate the 4th 32-bit part 4 times.
      *tmp2 = _mm_shuffle_epi32(*tmp, SHUFFLE4_32(3, 3, 3, 3));
      
      tmp4 = _mm_slli_si128(*tmp3, 0x4);
      *tmp3 = _mm_xor_si128(*tmp3, tmp4);
      
      *tmp3 = _mm_xor_si128(*tmp3, *tmp2);      
    }
    
    inline void Cryptor::expandKey192(const unsigned char *key,
                                      unsigned char *schedule) {
      __m128i *keySchedule = (__m128i*) schedule;

      // Save the first 128 bits of the key as the first one.
      __m128i tmp = _mm_loadu_si128((__m128i*) key);
      if (!bigEndian) {
        reverse_m128i(tmp); // swap byte-order => big-endian.
      }
      keySchedule[0] = tmp;

      // The next 64 bits as the second.
      unsigned char buf[128];
      memset(buf, 0, 128);
      memcpy(buf, key + 16, 64);
      
      __m128i tmp3 = _mm_loadu_si128((__m128i*) buf);
      if (!bigEndian) {
        reverse_m128i(tmp3); // swap byte-order => big-endian.
      }
      keySchedule[1] = tmp3;

      __m128i tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x1);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[1] =
        (__m128i) _mm_shuffle_pd((__m128d) keySchedule[1],
                                 (__m128d) tmp, 0);
      keySchedule[2] =
        (__m128i) _mm_shuffle_pd((__m128d) tmp, (__m128d) tmp3, 1);
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x2);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[3] = tmp;
      keySchedule[4] = tmp3;

      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x4);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[4] =
        (__m128i) _mm_shuffle_pd((__m128d) keySchedule[4],
                                 (__m128d) tmp, 0);
      keySchedule[5] = (__m128i) _mm_shuffle_pd((__m128d) tmp,
                                                (__m128d) tmp3, 1);
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x8);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[6] = tmp;
      keySchedule[7] = tmp3;
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[7] =
        (__m128i) _mm_shuffle_pd((__m128d) keySchedule[7],
                                 (__m128d) tmp, 0);
      keySchedule[8] = (__m128i) _mm_shuffle_pd((__m128d) tmp,
                                                (__m128d) tmp3, 1);
 
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[9] = tmp;
      keySchedule[10] = tmp3;
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[10] =
        (__m128i) _mm_shuffle_pd((__m128d) keySchedule[10],
                                 (__m128d) tmp, 0);
      keySchedule[11] = (__m128i) _mm_shuffle_pd((__m128d) tmp,
                                                 (__m128d) tmp3, 1);
 
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x80);
      assistKey192(&tmp, &tmp2, &tmp3);
      keySchedule[12] = tmp;
      keySchedule[13] = tmp3;      
    }

    void Cryptor::assistKey256_1(__m128i *tmp, __m128i *tmp2) {
      // Duplicate 4th part 4 times.
      *tmp2 = _mm_shuffle_epi32(*tmp2, SHUFFLE4_32(3, 3, 3, 3));
      
      __m128i tmp3 = _mm_slli_si128(*tmp, 0x4);
      *tmp = _mm_xor_si128(*tmp, tmp3);
      
      tmp3 = _mm_slli_si128(tmp3, 0x4);
      *tmp = _mm_xor_si128(*tmp, tmp3);
      
      tmp3 = _mm_slli_si128(tmp3, 0x4);
      *tmp = _mm_xor_si128(*tmp, tmp3);
      *tmp = _mm_xor_si128(*tmp, *tmp2);
    }
    
    void Cryptor::assistKey256_2(__m128i *tmp, __m128i *tmp2) {
      __m128i tmp4 = _mm_aeskeygenassist_si128(*tmp, 0x0);

      // Duplicate 3rd part 4 times.
      __m128i tmp3 = _mm_shuffle_epi32(tmp4, SHUFFLE4_32(2, 2, 2, 2));
      
      tmp4 = _mm_slli_si128(*tmp2, 0x4);
      
      *tmp2 = _mm_xor_si128(*tmp2, tmp4);
      tmp4 = _mm_slli_si128(tmp4, 0x4);
      
      *tmp2 = _mm_xor_si128(*tmp2, tmp4);
      tmp4 = _mm_slli_si128(tmp4, 0x4);
      
      *tmp2 = _mm_xor_si128(*tmp2, tmp4);
      *tmp2 = _mm_xor_si128(*tmp2, tmp3);
    }    

    void Cryptor::expandKey256(const unsigned char *key,
                               unsigned char *schedule) {
      __m128i *keySchedule = (__m128i*) schedule;

      // Save the first 128 bits of the key as the first one.
      __m128i tmp = _mm_loadu_si128((__m128i*) key);
      if (!bigEndian) {
        reverse_m128i(tmp); // swap byte-order => big-endian.
      }
      keySchedule[0] = tmp;

      // The next 128 bits as the second.
      __m128i tmp3 = _mm_loadu_si128((__m128i*) (key + 16));
      if (!bigEndian) {
        reverse_m128i(tmp3); // swap byte-order => big-endian.
      }
      keySchedule[1] = tmp3;      

      __m128i tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);

      assistKey256_1(&tmp, &tmp2);
      keySchedule[2] = tmp;

      assistKey256_2(&tmp, &tmp3);
      keySchedule[3] = tmp3;

      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
      assistKey256_1(&tmp, &tmp2);
      keySchedule[4] = tmp;
      assistKey256_2(&tmp, &tmp3);
      keySchedule[5] = tmp3;
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
      assistKey256_1(&tmp, &tmp2);
      keySchedule[6] = tmp;
      assistKey256_2(&tmp, &tmp3);
      keySchedule[7] = tmp3;
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
      assistKey256_1(&tmp, &tmp2);
      keySchedule[8] = tmp;
      assistKey256_2(&tmp, &tmp3);
      keySchedule[9] = tmp3;
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
      assistKey256_1(&tmp, &tmp2);
      keySchedule[10] = tmp;
      assistKey256_2(&tmp, &tmp3);
      keySchedule[11] = tmp3;
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
      assistKey256_1(&tmp, &tmp2);
      keySchedule[12] = tmp;
      assistKey256_2(&tmp, &tmp3);
      keySchedule[13] = tmp3;
      
      tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
      assistKey256_1(&tmp, &tmp2);
      keySchedule[14] = tmp;
    }

    void Cryptor::ecbEncrypt(const string &plaintext, const Key &key,
                             string *ciphertext,
                             unsigned char *schedule) {
      // Right now we just use the same length, but it should just be
      // a multiple of 16.
      ciphertext->resize(plaintext.size());

      int blocks = plaintext.size() / 16;
      if (plaintext.size() % 16) {
        blocks++;
      }

      __m128i tmp;
      __m128i *input = (__m128i*) plaintext.data();
      __m128i *output = (__m128i*) ciphertext->data();      
      __m128i *keySchedule = (__m128i*) schedule;
      int rounds = getRounds(key.size);
      
      for (int block = 0; block < blocks; block++) {
        // Get next 128-bit block.
        tmp = _mm_loadu_si128(&input[block]);

        // Swap byte-order => big-endian.
        if (!bigEndian) {        
          reverse_m128i(tmp); 
        }

        // Whitening step.
        tmp = _mm_xor_si128(tmp, keySchedule[0]);

        // Apply the AES rounds.
        int round = 1;
        for (; round < rounds; round++) {
          tmp = _mm_aesenc_si128(tmp, keySchedule[round]);
        }

        // And the last.
        tmp = _mm_aesenclast_si128(tmp, keySchedule[round]);

        // Swap byte-order => little-endian.        
        if (!bigEndian) {        
          reverse_m128i(tmp); 
        }
        
        // Save the encrypted block.
        _mm_storeu_si128(&output[block], tmp);
      }
    }
    
    void Cryptor::ecbDecrypt(const string &ciphertext, const Key &key,
                             string *plaintext,
                             unsigned char *schedule) {
      plaintext->resize(ciphertext.size());

      int blocks = ciphertext.size() / 16;
      if (ciphertext.size() % 16) {
        blocks++;
      }

      __m128i tmp;
      __m128i *input = (__m128i*) ciphertext.data();
      __m128i *output = (__m128i*) plaintext->data();      
      __m128i *keySchedule = (__m128i*) schedule;
      int rounds = getRounds(key.size);
      
      for (int block = 0; block < blocks; block++) {
        // Get next 128-bit block.
        tmp = _mm_loadu_si128(&input[block]);

        // Swap byte-order => big-endian.
        if (!bigEndian) {                
          reverse_m128i(tmp); 
        }

        // Whitening step.
        tmp = _mm_xor_si128(tmp, keySchedule[0]);

        // Apply the AES rounds.
        int round = 1;
        for (; round < rounds; round++) {
          tmp = _mm_aesdec_si128(tmp, keySchedule[round]);
        }

        // And the last.
        tmp = _mm_aesdeclast_si128(tmp, keySchedule[round]);

        // Swap byte-order => little-endian.
        if (!bigEndian) {                        
          reverse_m128i(tmp);
        }
        
        // Save the decrypted block.
        _mm_storeu_si128(&output[block], tmp);
      }      
    }
  }
}
