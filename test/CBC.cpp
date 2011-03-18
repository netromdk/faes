#include <string>
#include <iostream>
using namespace std;

#include "AES.h"
#include "Common.h"
using namespace FAES;
using namespace FAES::AES;

int main(int argc, char **argv) {
  Cryptor cryptor(CBC);

  Key key = cryptor.genKey(_128_BITS);
  cout << key << endl;

  string plaintext = "Hello CBC Mode!!";
  cout << "Plaintext: " << plaintext << endl;
  
  string ciphertext;
  cryptor.encrypt(plaintext, key, &ciphertext);
  cout << "Ciphertext: ";
  dumpString(ciphertext);

  string plaintext2;
  cryptor.decrypt(ciphertext, key, &plaintext2);
  cout << "Plaintext: " << plaintext2 << endl;
  
  return 0;
}
