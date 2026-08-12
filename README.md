# slim-data-crypt
A simple cryptography library which is specifically optimized for ARM architecture.

Supported Algorithms:
- SHA-2
- ChaCha20-Poly1305
- XChaCha20-Poly1305
- PBKDF2-HMAC-SHA256
- X25519
- Integer arithmetic

Please use command "make" to build tests,
and the test programs will be generated in ./bin directory.

WARNING: ARM NEON is required for ChaCha20 and XChaCha20 at this edition.
