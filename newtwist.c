#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto.h"

char		*progname;

static aes256_key_t	crypto_key;
static const EVP_CIPHER	*cipher;
static char		key_file[1024];

/************************************************************************
 ********************             ERROUT             ********************
 ************************************************************************/
void
errout(char *fmt, ...)
{
    va_list	ap;
    char	temp[256];

    sprintf(temp, "%s: ", progname);
    va_start(ap, fmt);
    vsprintf(temp+strlen(temp), fmt, ap);
    va_end(ap);
    if (errno)
	perror(temp);
    else
	fprintf(stderr, "%s\n", temp);
    exit(3);
}

/************************************************************************
 ********************          ENCODE_FILE           ********************
 ************************************************************************/
void
encode_file(FILE *infp, FILE *outfp)
{
    int		len;
    char	buf[4096];
    BIO		*b64, *cipher_bio, *file_bio;

    cipher_bio = BIO_new(BIO_f_cipher());
    BIO_set_cipher(cipher_bio, cipher, crypto_key.key, crypto_key.iv, 1);
    b64 = BIO_new(BIO_f_base64());
    file_bio = BIO_new_fp(outfp, BIO_NOCLOSE);
    BIO_push(cipher_bio, b64);
    BIO_push(b64, file_bio);

    while ((len = fread(buf, 1, sizeof(buf), infp)) > 0)
    {
	if (BIO_write(cipher_bio, buf, len) != len)
	{
	    crypto_log_errors();
	    errout("BIO_write failed");
	}
    }

    BIO_flush(cipher_bio);
    BIO_free_all(cipher_bio);
}

/************************************************************************
 ********************          DECODE_FILE           ********************
 ************************************************************************/
void
decode_file(FILE *infp, FILE *outfp)
{
    int		len;
    char	buf[4096];
    BIO		*b64, *file_bio, *cipher_bio;

    b64 = BIO_new(BIO_f_base64());
    file_bio = BIO_new_fp(infp, BIO_NOCLOSE);
    cipher_bio = BIO_new(BIO_f_cipher());
    BIO_set_cipher(cipher_bio, cipher, crypto_key.key, crypto_key.iv, 0);
    BIO_push(cipher_bio, b64);
    BIO_push(b64, file_bio);

    while ((len = BIO_read(cipher_bio, buf, sizeof(buf))) > 0)
	fwrite(buf, len, 1, outfp);

    if (len < 0)
    {
	crypto_log_errors();
	errout("BIO_read failed");
    }

    BIO_free_all(cipher_bio);
}

/************************************************************************
 ********************              MAIN              ********************
 ************************************************************************/
int
main(int argc, char *argv[])
{
    int		i;
    char	*home, *config_dir;
    static char *v[] = { "-v", "--verbose" };

    progname = argv[0];
    for (i = strlen(progname) - 1; i >= 0 && progname[i] != '/'; --i);
    progname += (i + 1);

    if (argc == 2 && (strcmp(argv[1], v[0]) == 0 || strcmp(argv[1], v[1]) == 0))
    {
	printf("%s version %s\n", progname, VERSION);
	exit(0);
    }

    if ((home = getenv("HOME")) == NULL)
	errout("HOME environment variable not set");
    if (crypto_init(home) < 0)
	errout("crypto_init() failed: %s", crypto_strings(CRYPTO_ERROR));
    config_dir = crypto_strings(CRYPTO_CONFIG_DIR);

    snprintf(key_file, sizeof(key_file), "%s/.keyfile", config_dir);
    if (get_key_from_file(key_file, &crypto_key) < 0)
	errout("get_key_from_file failed: %s", crypto_strings(CRYPTO_ERROR));
    cipher = EVP_aes_256_cfb128();

    if (strcmp(progname, "newtwist") == 0 || strcmp(progname, "twist") == 0)
	encode_file(stdin, stdout);
    else
	decode_file(stdin, stdout);

    // On successful exit, delete the log file
    unlink(crypto_strings(CRYPTO_LOGFILE));
    exit(0);
}
