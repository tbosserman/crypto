#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/blowfish.h>

static char	*progname;

/************************************************************************
 ********************             ERROUT             ********************
 ************************************************************************/
static void
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
 ********************         INITIALIZE_KEY         ********************
 ************************************************************************/
static void
initialize_key(BF_KEY *key)
{ 
    uid_t	uid;
    mode_t	mode;
    char	*home, rcfile[MAXPATHLEN];
    u_char	*ptr, *data;
    int		fd, datalen, templen, len;
    struct stat	st;

    errno = 0;
    if ((home = getenv("HOME")) == NULL)
	errout("getenv(HOME) failed");
    uid = getuid();
    if (strlen(home) + 10 >= MAXPATHLEN)
	errout("path to .twistrc file too long");
    sprintf(rcfile, "%s/.twistrc", home);
    errno = 0;
    if (stat(rcfile, &st) < 0)
	errout("stat() of %s failed", rcfile);
    if (uid != st.st_uid)
	errout("you do not own %s", rcfile);
    mode = st.st_mode & 0777;
    if (mode != 0600 && mode != 0400)
	errout("wrong permissions on %s", rcfile);
    datalen = st.st_size;
    if ((data = malloc(datalen)) == NULL)
	errout("error allocating buffer");
    if ((fd = open(rcfile, O_RDONLY)) < 0)
	errout("error opening %s for reading", rcfile);

    ptr = data;
    templen = datalen;
    while (templen > 0)
    {
	if ((len = read(fd, ptr, templen)) < 0)
	    errout("error reading from %s", rcfile);
	ptr += len;
	templen -= len;
    }

    BF_set_key(key, datalen, data);
    memset(data, 0, datalen);
    free(data);
}

/************************************************************************
 ********************           GET64BITS            ********************
 ************************************************************************/
static int
get64bits(FILE *fp, u_char *decrypted)
{
    int			i, j, ch, temp[2];
    u_char		buffer[8];
    static int		initialized;
    static BF_KEY	key;

    i = 0;
    while (i < 8)
    {
	j = 0;
	while (j < 2)
	{
	    if ((ch = getc(fp)) == EOF)
		return(EOF);
	    if (ch != '\n' && isxdigit(ch))
	    {
		if (islower(ch))
		    ch = toupper(ch);
		ch = isalpha(ch) ? (10 + ch - 'A') : ch - '0';
		temp[j++] = ch;
	    }
	}
	buffer[i++] = (temp[0] << 4) | temp[1];
    }

    if (!initialized)
    {
	initialize_key(&key);
	initialized = 1;
    }

    BF_ecb_encrypt(buffer, decrypted, &key, BF_DECRYPT);
    return(0);
}

/************************************************************************
 ********************          FILL_BUFFER           ********************
 ************************************************************************/
static int
fill_buffer(FILE *fp, u_char *buffer)
{
    int		buflen, nblks;
    u_char	decrypted[8], *bufptr;

    if (get64bits(fp, decrypted) == EOF)
	return(EOF);
    buflen = decrypted[0];
    bufptr = buffer;
    memcpy(bufptr, decrypted+1, 7);
    bufptr += 7;
    nblks = buflen / 8;
    while (nblks-- > 0)
    {
	if (get64bits(fp, bufptr) == EOF)
	    return(EOF);
	bufptr += 8;
    }
    return(buflen);
}

/************************************************************************
 ********************            GETCHAR             ********************
 ************************************************************************/
static int
getbyte(FILE *fp)
{
    static u_char	buffer[264];
    static int		buflen, bufindex;

    if (bufindex >= buflen)
    {
	buflen = fill_buffer(fp, buffer);
	if (buflen == EOF)
	    return(EOF);
	bufindex = 0;
    }

    return(buffer[bufindex++]);
}

/************************************************************************
 ********************            NEXTLINE            ********************
 ************************************************************************/
static int
nextline(FILE *fp, char *line, int maxlen)
{
    int		i, ch;

    i = ch = 0;
    --maxlen;
    while (i < maxlen && (ch = getbyte(fp)) != EOF)
    {
	if (ch == '\n')
	    break;
	line[i] = ch;
	++i;
    }
    line[i] = '\0';
    if (i == 0 && ch == EOF)
	return(EOF);
    else
	return(i);
}

/************************************************************************
 ********************            TWISTIT             ********************
 ************************************************************************/
static void
twistit()
{
    int		i, len, outcount, nblks;
    u_char	in[256], out[8], *ptr;
    BF_KEY	key;

    initialize_key(&key);
    outcount = 0;
    memset(in, 0, sizeof(in));
    len = fread(in+1, 1, 255, stdin);
    while(len > 0 && !ferror(stdin))
    {
	in[0] = (u_char)len;
	nblks = (len + 8) / 8;
	ptr = in;
	while (nblks-- > 0)
	{
	    BF_ecb_encrypt(ptr, out, &key, BF_ENCRYPT);
	    ptr += 8;
	    for (i = 0; i < 8; ++i) printf("%02X", out[i]);
	    if (++outcount % 4 == 0)
		putchar('\n');
	}

	memset(in, 0, sizeof(in));
	len = fread(in+1, 1, 255, stdin);
    }
    if (ferror(stdin))
	errout("error reading from stdin");
    if (outcount % 4 != 0)
	putchar('\n');
}

/************************************************************************
 ********************              MAIN              ********************
 ************************************************************************/
int
main(int argc, char *argv[])
{
    int		i;
    char	line[1024];

    progname = argv[0];
    for (i = strlen(progname) - 1; i >= 0 && progname[i] != '/'; --i);
    progname += (i + 1);

    if (strcmp(progname, "untwist") == 0)
    {
	while (nextline(stdin, line, sizeof(line)) >= 0) puts(line);
    }
    else
	twistit();

    exit(0);
}
