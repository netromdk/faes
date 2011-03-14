#include <string>
#include <iostream>
using namespace std;

#include "AES.h"
using namespace FAES::AES;

void dumpString(string &data) {
  cout << "[" << data.size() << "] ";
  
  for (int i = 0; i < data.size(); i++) {
    cout << (int) data[i] << " ";
  }
  
  cout << endl;
}

int main(int argc, char **argv) {
  Cryptor cryptor(ECB);

  Key key = cryptor.genKey(_128_BITS);
  cout << key << endl;

  string plaintext = "Hello ECB Mode!!";
  cout << "Plaintext: " << plaintext << endl;
  dumpString(plaintext);
  
  string ciphertext;
  cryptor.encrypt(plaintext, key, &ciphertext);
  cout << "Ciphertext: " << ciphertext << endl;
  dumpString(ciphertext);  

  string plaintext2;
  cryptor.decrypt(ciphertext, key, &plaintext2);
  cout << "Plaintext: " << plaintext2 << endl;
  dumpString(plaintext2);    
  
  return 0;
}
