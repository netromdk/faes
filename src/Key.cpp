#include "Key.h"
using namespace std;

namespace FAES {
  namespace AES {
    Key::Key(KeySize size) : iv(NULL), nonce(NULL), size(size) {
      key = new unsigned char[size];
    }
    
    Key::~Key() {
      delete[] key;
      delete[] iv;
      delete[] nonce;
    }
    
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
  }
}
