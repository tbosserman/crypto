## OpenSSL / Cryptography Toys

This repository contains some "toy" programs & modules for playing around
with cryptography in OpenSSL. I publish it here just in case somebody
stumbles upon it and finds it useful as a learning tool. Please don't
trust this code too much. I'm sure there are bugs in it. Also, it
relies a little bit on Unix / Linux permissions and "security by
obscurity" for its security model. It definitely won't qualify for
any kind of ISO certification! It's just some toys for playing around
with and learning.

### History

Back in the late 1990s (jeez, nearly 30 years ago!) I was just starting to
learn how to use the OpenSSL API. One of my very first programs was called
"twist", and it simply encrypted a file, base64-encoded it, and wrote
the result to stdout. If you linked twist to the name "untwist", it would
do the opposite: base64-decode and decrypt a file and write the results
to stdout. It's pretty primitive, and it's pretty ugly. I also did things
"the hard way". There are MUCH easier-to-use APIs in OpenSSL than the
way I did it. But I learned a lot playing around with it. The program was
useful enough that I've actually kept using it all these years.

But time passes and now that program gets a lot of "deprecation" warnings
when you compile it. So I started playing around with a newer, more
modern replacement for it. The new program uses the BIO_* functions and
uses the much more modern 256-bit AES encryption ciphers. I also think
this code is (at least slightly) less "ugly" and more readable. It also doesn't
generate any warnings when you compile it.

### Files

crypto.c - Some general purpose functions including a logger. The main
functions intended to be public-facing:

- crypto_init(char *home) - Initializes everything so the other functions work.
- crypto_log(char *fmt, ...) - Logs to ~/.config/crypto/crypto.log. Not really
intended for the public, but sure, go ahead and use it if you like.
- encode_buf() - Encrypts and base64-encodes an in-memory buffer.
- decode_buf() - Base64-decodes and decrypts an in-memory buffer.
- store_key() - Stores a key in a file after encrypting it with an "internal"
key and base64-encoding it.
- load_key() - Loads a key from a file that was generated via the store_key()
function.
- get_key_from_file() - A higher level function that calls load_key() to do
the work. If the file doesn't exist yet, a new key is generated and stored
in the file.
- crypto_strings(int which) Returns various internal variables:
    - CRYPTO_ERROR: the last error message stored internally.
    - CRYPTO_CONFIG_DIR: the config dir.
    - CRYPTO_LOGFILE: the file to which it is logging.

crypto.h - The include file with all the definitions.

newtwist.c - A program to essentially do what the old "twist" program does:
If run as a program named "newtwist" or "twist", it encrypts stdin,
base64-encodes it, and writes it to stdout. If run as "newuntwist" or
"untwist" it does the opposite: base64-decodes and decrypts stdin and writes
the result to stdout.

orig_twist.c - The original program I wrote back in the 1990s. It still works!
