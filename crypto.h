#include <sys/types.h>

#define KEYLEN          32
#define IVLEN           16

#define CRYPTO_ERROR		0
#define CRYPTO_CONFIG_DIR	1
#define CRYPTO_LOGFILE		2

typedef struct {
    u_int8_t	key[KEYLEN];
    u_int8_t	iv[IVLEN];
} aes256_key_t;

extern int crypto_init(char *home);
extern int encode_buf(u_int8_t *src, u_int8_t *dst, int srclen, int dstlen,
    aes256_key_t *aeskey);
extern int decode_buf(u_int8_t *src, u_int8_t *dst, int srclen, int dstlen,
    aes256_key_t *aeskey);
extern int store_key(char *fname, aes256_key_t *key);
extern int load_key(char *fname, aes256_key_t *key);
extern int gen_aeskey(aes256_key_t *key);
extern int get_key_from_file(char *key_file, aes256_key_t *key);
extern char *crypto_strings(int);
extern void crypto_log_errors();
