# slim-data-crypt
A simple cryptography library which is specifically optimized for ARM architecture and easy to use.<br>
But it is not limited to ARM architecture, you can use it on other architectures, although it will fallback to scalar implementation on other architectures.

Supported Algorithms and Functions:
- SHA-2 (with hash interface)
- ChaCha20-Poly1305
- XChaCha20-Poly1305
- PBKDF2-HMAC-SHA256
- X25519
- Integer arithmetic
- ASN.1 parse and write

How to build tests:
- On Linux or Termux (Android), you can directly use "make".
- On Windows, you should use "make (or mingw32-make) -f Makefile.win".
All test programs will be generated in ./bin directory.