#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto.h"

static int key_indexes[KEYLEN] = { 
     255, 144,  94, 194,  13,  31, 180, 232, 241,  21, 177, 226,
     222,  84, 197,   8, 101, 240,  91, 175,  34,  79, 196, 203,
     226,   3,   6, 208,  54,  27,  77,  54
};

static int iv_indexes[IVLEN] = { 
     171, 171, 248, 184, 202, 172, 161, 187, 193,  82, 158, 160,
     166,  99, 168,  11
};

static u_int8_t random_data[256];
static u_int8_t internal_key[KEYLEN];
static u_int8_t internal_iv[IVLEN];
static char last_error[2048];
static char config_dir[896], logfile[1024];
static FILE *logfp;

/************************************************************************
 ********************            MKDIR_P             ********************
 ************************************************************************/
int
mkdir_p(char *dirname)
{
    int		maxlen;
    char	*name, so_far[1024], dirname_copy[1024];
    struct stat	st;

    // strtok destroys its arg, so we make a copy and operate on that.
    strncpy(dirname_copy, dirname, sizeof(dirname_copy));
    so_far[0] = '\0';
    maxlen = sizeof(so_far);
    name = strtok(dirname_copy, "/");
    while (name && maxlen > strlen(name))
    {
	strcat(so_far, "/");
	strcat(so_far, name);
	if (stat(so_far, &st) != 0)
	{
	    if (mkdir(so_far, 0700) < 0)
		return(-1);
	}
	name = strtok(NULL, "/");
	maxlen = sizeof(so_far) - strlen(so_far);
    }
    return(0);
}

/************************************************************************
 ********************          CRYPTO_INIT           ********************
 ************************************************************************/
int
crypto_init(char *home)
{
    int		i, fd, rndfd, len;
    struct stat	st;
    char	fname[1024];

    fname[sizeof(fname)-1] = '\0';
    snprintf(fname, sizeof(fname)-1, "%s/.crypto", home);
    len = sizeof(random_data);
    if (stat(fname, &st) < 0)
    {
	if ((rndfd = open("/dev/urandom", O_RDONLY)) < 0)
	    return(-1);
	if (read(rndfd, random_data, len) != len)
	    return(-1);
	if ((fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
	    return(-1);

	if (write(fd, random_data, len) != len)
	    return(-1);
	if (fchmod(fd, 0400) < 0)
	    return(-1);
	close(fd);
	close(rndfd);
    }
    else
    {
	if ((fd = open(fname, O_RDONLY)) < 0)
	    return(-1);
	if (read(fd, random_data, len) != len)
	    return(-1);
	close(fd);
    }

    for (i = 0; i < KEYLEN; ++i)
	internal_key[i] = random_data[key_indexes[i]];
    for (i = 0; i < IVLEN; ++i)
	internal_iv[i] = random_data[iv_indexes[i]];

    // Initialize the logging "subsystem"
    snprintf(config_dir, sizeof(config_dir), "%s/.config/crypto", home);
    if (mkdir_p(config_dir) < 0)
    {
	snprintf(last_error, sizeof(last_error),
	    "error creating directory %s", config_dir);
	return(-1);
    }

    snprintf(logfile, sizeof(logfile), "%s/crypto.log", config_dir);
    if ((logfp = fopen(logfile, "w")) == NULL)
    {
	snprintf(last_error, sizeof(last_error),
	    "error opening %s for writing", logfile);
	return(-1);
    }
    fchmod(fileno(logfp), 0600);

    return(0);
}

/************************************************************************
 ********************          CRYPTO_LOG            ********************
 ************************************************************************/
void
crypto_log(char *fmt, ...)
{
    va_list             ap;
    time_t              now;
    struct tm           *tm;

    now = time(NULL);
    tm = localtime(&now);
    fprintf(logfp, "%02d:%02d:%02d ", tm->tm_hour, tm->tm_min, tm->tm_sec);
    va_start(ap, fmt);
    vfprintf(logfp, fmt, ap);
    va_end(ap);
    fflush(logfp);
}

/************************************************************************
 ********************       CRYPTO_LOG_ERRORS        ********************
 ************************************************************************/
void
crypto_log_errors()
{
    int		err;
    char	errbuf[1024];

    while ((err = ERR_get_error()) != 0)
    {
	crypto_log("err=%d\n", err);
	crypto_log("    %s\n", ERR_error_string(err, errbuf));
    }
}

/************************************************************************
 ********************           DECODE_BUF           ********************
 ************************************************************************/
int
decode_buf(u_int8_t *src, u_int8_t *dst, int srclen, int dstlen,
    aes256_key_t *aeskey)
{
    int		len, readlen;
    u_int8_t	*bufp, *key, *iv;
    BIO		*b64, *membuf, *cipher_bio;
    const EVP_CIPHER	*cipher;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    membuf = BIO_new(BIO_s_mem());
    cipher = EVP_aes_256_cfb128();
    cipher_bio = BIO_new(BIO_f_cipher());
    if (aeskey == NULL)
    {
	key = internal_key;
	iv = internal_iv;
    }
    else
    {
	key = aeskey->key;
	iv = aeskey->iv;
    }
    BIO_set_cipher(cipher_bio, cipher, key, iv, 0);

    BIO_push(b64, membuf);
    BIO_push(cipher_bio, b64);

    if ((len = BIO_write(membuf, src, srclen)) <= 0)
	crypto_log_errors();
    if (len != srclen)
	return(-1);

    BIO_flush(membuf);

    readlen = 0;
    bufp = dst;
    while (dstlen > 0 && (len = BIO_read(cipher_bio, bufp, dstlen)) > 0)
    {
	bufp += len;
	readlen += len;
	dstlen -= len;
    }

    if (len < 0)
    {
	crypto_log_errors();
	BIO_free_all(membuf);
	return(-1);
    }
    BIO_free_all(membuf);

    return(readlen);
}

/************************************************************************
 ********************           ENCODE_BUF           ********************
 ************************************************************************/
int
encode_buf(u_int8_t *src, u_int8_t *dst, int srclen, int dstlen,
    aes256_key_t *aeskey)
{
    int		len, writelen;
    u_int8_t	*bufp, *key, *iv;
    BIO		*b64, *membuf, *cipher_bio;
    const EVP_CIPHER	*cipher;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    membuf = BIO_new(BIO_s_mem());
    cipher = EVP_aes_256_cfb128();
    cipher_bio = BIO_new(BIO_f_cipher());
    if (aeskey == NULL)
    {
	key = internal_key;
	iv = internal_iv;
    }
    else
    {
	key = aeskey->key;
	iv = aeskey->iv;
    }
    BIO_set_cipher(cipher_bio, cipher, key, iv, 1);
    BIO_push(cipher_bio, b64); BIO_push(b64, membuf);

    if ((len = BIO_write(cipher_bio, src, srclen)) != srclen)
    {
	crypto_log_errors();
	return(-1);
    }

    BIO_flush(cipher_bio);

    writelen = 0;
    bufp = dst;
    while (dstlen > 0 && (len = BIO_read(membuf, bufp, dstlen)) > 0)
    {
	bufp += len;
	writelen += len;
	dstlen -= len;
    }
    if (len < 0)
    {
	crypto_log_errors();
	BIO_free_all(cipher_bio);
	return(-1);
    }

    BIO_free_all(cipher_bio);

    return(writelen);
}

/************************************************************************
 ********************           GEN_AESKEY           ********************
 ************************************************************************/
int
gen_aeskey(aes256_key_t *key)
{
    int		fd, len;

    if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
	return(-1);
    if ((len = read(fd, key->key, KEYLEN)) < 0)
	return(-1);
    if (len != KEYLEN)
	return(-1);

    if ((len = read(fd, key->iv, IVLEN)) < 0)
	return(-1);
    if (len != IVLEN)
	return(-1);

    return(0);
}

/************************************************************************
 ********************           STORE_KEY            ********************
 ************************************************************************/
int
store_key(char *fname, aes256_key_t *key)
{
    FILE	*fp;
    int		len, enclen;
    char	encoded[1024];

    if ((fp = fopen(fname, "w")) == NULL)
	return(-1);
    if (chmod(fname, 0400) < 0)
	return(-1);

    enclen = sizeof(encoded);
    len = encode_buf(key->key, (u_int8_t *)encoded, KEYLEN, enclen, NULL);
    encoded[len] = '\0';
    fprintf(fp, "%s\n", encoded);

    len = encode_buf(key->iv, (u_int8_t *)encoded, IVLEN, enclen, NULL);
    encoded[len] = '\0';
    fprintf(fp, "%s\n", encoded);

    fclose(fp);

    return(0);
}

/************************************************************************
 ********************            LOAD_KEY            ********************
 ************************************************************************/
int
load_key(char *fname, aes256_key_t *key)
{
    FILE	*fp;
    uid_t	uid;
    mode_t	mode;
    int		len, linelen;
    char	line[1024];
    struct stat	st;

    // Check permissions and ownership of the key file
    uid = getuid();
    if (stat(fname, &st) < 0)
    {
        crypto_log("stat(%s) failed: %s", fname, strerror(errno));
	return(-1);
    }
    if (uid != st.st_uid)
    {
        crypto_log("you do not own %s", fname);
	return(-1);
    }
    mode = st.st_mode & 0777;
    if (mode != 0600 && mode != 0400)
    {
        crypto_log("wrong permissions on %s", fname);
	return(-1);
    }

    if ((fp = fopen(fname, "r")) == NULL)
    {
	crypto_log("error opening %s for reading: %s", fname, strerror(errno));
	return(-1);
    }

    line[sizeof(line)-1] = '\0';
    if (fgets(line, sizeof(line)-1, fp) == NULL)
	return(-1);
    linelen = strlen(line);
    line[--linelen] = '\0';
    len = decode_buf((u_int8_t *)line, key->key, linelen, KEYLEN, NULL);
    if (len != KEYLEN)
    {
	fclose(fp);
	return(-1);
    }

    if (fgets(line, sizeof(line)-1, fp) == NULL)
	return(-1);

    fclose(fp);
    linelen = strlen(line);
    line[--linelen] = '\0';
    len = decode_buf((u_int8_t *)line, key->iv, linelen, IVLEN, NULL);
    if (len != IVLEN)
	return(-1);

    return(0);
}

/************************************************************************
 ********************          STORE_ERROR           ********************
 ************************************************************************/
int
store_error(int code, char *fmt, ...)
{
    va_list	ap;

    va_start(ap, fmt);
    vsnprintf(last_error, sizeof(last_error), fmt, ap);
    va_end(ap);
    return(code);
}

/************************************************************************
 ********************       GET_KEY_FROM_FILE        ********************
 ************************************************************************/
int
get_key_from_file(char *key_file, aes256_key_t *key)
{
    if (access(key_file, F_OK) < 0)
    {
	if (gen_aeskey(key) < 0)
	    return(store_error(-1, "Unable to generate crypto key"));
	if (store_key(key_file, key) < 0)
	    return(store_error(-1, "error writing to %s: %s", key_file,
		strerror(errno)));
    }
    else
    {
	if (load_key(key_file, key) < 0)
	    return(store_error(-1, "error reading %s", key_file,
		strerror(errno)));
    }
    return(0);
}

/************************************************************************
 ********************         CRYPTO_STRINGS         ********************
 ************************************************************************/
char *
crypto_strings(int which)
{
    switch(which)
    {
	case CRYPTO_ERROR:
	    return(last_error);
	case CRYPTO_CONFIG_DIR:
	    return(config_dir);
	case CRYPTO_LOGFILE:
	    return(logfile);
	default:
	    return(NULL);
    }
}
