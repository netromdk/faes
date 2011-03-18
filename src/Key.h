#ifndef KEY_H
#define KEY_H

#include <string>
#include <cstddef>
#include <sstream>

#include "Common.h"
#include "KeySize.h"

namespace FAES {
  namespace AES {
    class Key {
    public:
      Key(KeySize size);
      ~Key();

      std::string toString() const;

      // iv and nonce should be terminated with a \0.
      ALIGN16 unsigned char *key, *iv, *nonce;
      KeySize size;
    };

    std::ostream &operator<<(std::ostream &os, const Key &key);
  }
}

#endif // KEY_H
