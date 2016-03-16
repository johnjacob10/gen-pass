#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>          /* for basename() */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <bzlib.h>           /* needs libbz2 library installed */
#include <gmp.h>             /* needs GNU MP library installed */

#ifndef DEBUG                /* compile with -DDEBUG=1 to enable debug logs */
  #define DEBUG       0
#endif

#define ERR           -1
#define OK            0
#define HEX           16
#define ESC           27

#define BUF_LEN       1024   /* sufficient for a fairly random data input */
#define EXE_LEN       32     /* to hold program invocation name */
#define MIN_BUF_CHARS 24     /* 2^(MIN_BUF_CHARS*8) > SYM_TAB_LEN^PASS_LEN */
#define PASS_LEN      28     /* sufficient to avoid most brute force attacks */
#define SYM_TAB_LEN   sizeof(sym_tab)

/* compile with -DDEBUG=1 to enable debug logs */
const unsigned int debug_enabled = DEBUG;

/*
 * This is a list of password characters that are valid for the majority
 * of applications. This list is obtained from the following resource.
 * http://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/windows_password_tips.mspx
 * If a particular application does not accept some characters from this list,
 * then delete those characters from the generated password before using it
 */
const unsigned char sym_tab[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
    'W', 'X', 'Y', 'Z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '`', '~',
    '!', '@', '#', '$', '%', '^', '&', '*',
    '(', ')', '_', '+', '-', '=', '{', '}',
    '|', '[', ']', '\\', ':', '"', ';', '\'',
    '<', '>', '?', ',', '.', '/'
};

static int get_file_len (int fdesc, off_t *len)
{
    struct stat info;
    if ((len == NULL) || (fstat(fdesc, &info) != OK)) {
        return (ERR);
    }

    *len = info.st_size;
    return (OK);
}

static int read_file_data (FILE *fdesc, unsigned char *buf, off_t offset)
{
    if ((fdesc == NULL) || (buf == NULL)) {
        return (ERR);
    }

    if (fseeko(fdesc, offset, SEEK_SET) != OK) {
        return (ERR);
    }        

    if (fread(buf, BUF_LEN, 1, fdesc) < 1) {
        return (ERR);
    }

    return (OK);
}

static int compress_data (char *inp, char *outp, unsigned int *out_bytes)
{
    bz_stream strm;
    int status = ERR;

    if ((inp == NULL) || (outp == NULL) || (out_bytes == NULL)) {
        return (status);
    }

    memset(outp, 0, BUF_LEN);
    memset(&strm, 0, sizeof(bz_stream));
    strm.next_in = inp;
    strm.next_out = outp;
    strm.avail_in = BUF_LEN;
    strm.avail_out = BUF_LEN;

    if (BZ2_bzCompressInit(&strm, 9, 0, 0) != BZ_OK) {
        return (status);
    }

    if (BZ2_bzCompress(&strm, BZ_RUN) == BZ_RUN_OK) {
        while (1) {
            status = BZ2_bzCompress(&strm, BZ_FINISH);
            if ((status == BZ_FINISH_OK) || (status == BZ_STREAM_END)) {
                *out_bytes = strm.total_out_lo32;
                status = OK;
                break;
            }
        }
    }

    (void) BZ2_bzCompressEnd(&strm);
    return (status);
}

static int convert_num (unsigned char * inp_buf, int inp_len,
                        unsigned char * out_buf, int out_len)
{
    mpz_t val, quot;
    const unsigned long mod = SYM_TAB_LEN;
    int count;
    unsigned char digit;

    count =  out_len - 1;

    mpz_init_set_str(val, inp_buf, HEX);
    mpz_init(quot);

    while (count >= 0) {
        /* 
         * digit = val % mod;
         * quot = val / mod;
         */
        digit = mpz_tdiv_q_ui(quot, val, mod);
        out_buf[count] = sym_tab[digit];
        count --;

        if (!count && (mpz_cmpabs_ui(quot, mod) <= 0)) {
            fprintf(stderr,
                    "Error: input quenched before output generated.\n");
            return (ERR);
        }

        /* val = quot */        
        mpz_set(val, quot);
    }

    /* this should not be a big deal */
    if (mpz_cmpabs_ui(val, mod) > 0) {
        if (debug_enabled) {
            fprintf(stderr, "Warning: input buffer incompletely used.\n");
        }
    }
    
    return (OK);
}
 
/*
 * This function converts a hexadecimal value in to the equivalent character
 * representation. For example, the value 14 is converted in to the character
 * 'E'.
 */
static unsigned char hex_text (unsigned char value)
{
    unsigned char ret = (unsigned char) -1;

    switch (value) {
        case 0 : ret = '0'; break;
        case 1 : ret = '1'; break;
        case 2 : ret = '2'; break;
        case 3 : ret = '3'; break;
        case 4 : ret = '4'; break;
        case 5 : ret = '5'; break;
        case 6 : ret = '6'; break;
        case 7 : ret = '7'; break;
        case 8 : ret = '8'; break;
        case 9 : ret = '9'; break;
        case 10: ret = 'A'; break;
        case 11: ret = 'B'; break;
        case 12: ret = 'C'; break;
        case 13: ret = 'D'; break;
        case 14: ret = 'E'; break;
        case 15: ret = 'F'; break;
        default: fprintf(stderr,
                         "Error: bad value %u for hex conversion.\n", value);
                 exit(ERR);
    }
    return (ret);
}

/*
 * This function generates a password of len characters from the random input
 * data. The input data can be thought of as a large hex number. We need to
 * convert it into a number of base 94, since there are 94 characters that are
 * valid for passwords. We can then iterate along the number to pick the 
 * characters to use in our password.
 *
 * We need to convert the input data from a binary buffer (base-256) to a
 * hexadecimal string because the GMP function mpz_init_set_str has a limit of
 * base-63 for its input.
 */
static int generate_pass (unsigned char * data, int bytes,
                          unsigned char * pass, int len)
{
    char * b16data;
    int count, b16len, ret;

    /*
     * Note that data is a binary buffer. It is not null terminated. b16data
     * is an output string. It IS null terminated. This is why it is an extra
     * byte long.
     */
    b16len = (bytes * 2) + 1;
    b16data = malloc(b16len);
    if (b16data == NULL) {
        fprintf(stderr, "Error: insufficient memory.\n");
        return (ERR);
    }
    
    memset(b16data, 0, b16len);
    for (count = 0; count < bytes; count++) {
        b16data[count * 2]       = hex_text((data[count] & 0xf0) >> 4);
        b16data[(count * 2) + 1] = hex_text(data[count] & 0x0f);
    }

    if (debug_enabled) {
        fprintf(stdout, "Info: Input hex string is %d bytes and is %s\n",
                b16len, b16data);
        fflush(stdout);
    }

    ret = convert_num(b16data, b16len, pass, len);
    memset(b16data, 0, b16len);
    free(b16data);

    return (ret);
}

void clear_screen (void)
{
    /*
     * Try to overflow the console buffer so that the command line is no
     * longer visible
     */
    unsigned int i = 512, j;
    while (i) {
        j = 4096;
        while (j) {
            if ((j % 2) == 0) {
                fprintf(stderr, "A");
                fprintf(stdout, "Z");
            } else {
                fprintf(stderr, "Y");
                fprintf(stdout, "B");
            }
            j--;
            fflush(stderr);
            fflush(stdout);
        }
        fprintf(stderr, "%c[2J", (char) ESC);
        fprintf(stdout, "%c[2J", (char) ESC);
        i--;
    }
    return;
}

/*
 * Remember to use the shell HISTIGNORE environment variable to prevent this
 * command from being remembered!
 */
int main (int argc, char *argv[])
{
    FILE *inp = NULL;
    off_t len = 0, offset = 0;
    unsigned int out_len, fd, ret = ERR;
    unsigned char *in_buf, *out_buf, *pass, *histignore, progname[EXE_LEN];
    
    if (argc < 2) {
        fprintf(stderr, "Error: Invalid arguments\n");
        fprintf(stderr, "Usage: %s <file> [<offset>]\n", argv[0]);
        exit(ret);
    }

    histignore = getenv("HISTIGNORE");
    snprintf(progname, EXE_LEN, "*%s*", basename(argv[0]));
    if ((histignore == NULL) ||
        (strstr(histignore, progname) == NULL)) {
        clear_screen();
        fprintf(stderr,
                "%c[2J\nError: use \'export HISTIGNORE=\"*%s*\"\' to direct "
                "the shell to forget this command\n", (char) ESC, progname);
        exit(ret);
    }

    fd = open(argv[1], O_RDONLY, 0);
    if (fd == ERR) {
        fprintf(stderr, "Error: Unable to open file %s\n", argv[1]);
        exit(1);
    }

    if (get_file_len(fd, &len) != OK) {
        fprintf(stderr, "Error: Unable to determine file attributes\n");
        close(fd);
        exit(ret);
    }

    inp = fdopen(fd, "rb");
    if (inp == NULL) {
        fprintf(stderr, "Error: Unable to stream file %s\n", argv[1]);
        close(fd);
        exit(ret);
    }

    if (argc == 3) {
        offset = (off_t) strtoll( argv[2], NULL, 0);
    }

    if ((signed) offset < 0) {
        fprintf(stderr, "Error: Negative offset specified\n");
        fclose(inp);
        close(fd);
        exit(ret);
    }

    if (((offset + BUF_LEN) < BUF_LEN ) || /* wrapped */
        (len < (offset + BUF_LEN))) {
        fprintf(stderr, "Error: File too small or offset too large\n");
        fclose(inp);
        close(fd);
        exit(ret);
    }

    in_buf = malloc(BUF_LEN);
    if (in_buf == NULL) {
        fprintf(stderr, "Error: Insufficient memory\n");
        fclose(inp);
        close(fd);
        exit(ret);
    }

    if (read_file_data(inp, in_buf, offset) != OK) {
        fprintf(stderr, "Error: Unable to read from file\n");
        free(in_buf);
        fclose(inp);
        close(fd);
        exit(ret);
    }

    /*
     * Now that we have read the file data, we don't need the file handle
     * any more
     */
    fclose(inp);
    close(fd);

    out_buf = malloc(BUF_LEN);
    if (out_buf == NULL) {
        fprintf(stderr, "Error: insufficient memory\n");
        free(in_buf);
        exit(ret);
    }

    if (compress_data((char *)in_buf, (char *)out_buf, &out_len) != OK) {
        fprintf(stderr, "Error: Compression failure\n");
        free(in_buf);
        free(out_buf);
        exit(ret);
    }
    
    if (debug_enabled) {
        fprintf(stdout, "Info: compression ratio is %d:%d\n", BUF_LEN,
                out_len);
    }

    if (out_len < MIN_BUF_CHARS) {
        fprintf(stderr, "Error: Input file data has insufficient entropy\n");
        free(in_buf);
        free(out_buf);
        exit(ret);
    } else if (out_len >= BUF_LEN) {
        /* input data is incompressible, so let us use it directly */
        memset(out_buf, 0, BUF_LEN);
        free(out_buf);
        out_buf = in_buf;
        out_len = BUF_LEN;
    } else {        
        /*
         * Now that we have the output data, we don't need the input buffer.
         * So clear it now as otherwise the data could remain in memory until
         * the dirty pages are flushed or reused by the OS. Of course, the 
         * standard output console memory will retain the password, and there
         * is no way for us to clear that.
         */
        memset(in_buf, 0, BUF_LEN);
        free(in_buf);
    }

    pass = malloc(PASS_LEN + 1);
    if (pass == NULL) {
        fprintf(stderr, "Error: Insufficient memory\n");
    } else {
        memset(pass, 0, PASS_LEN + 1);
        if (generate_pass(out_buf, out_len,
                          pass, PASS_LEN + 1) == OK) {
            fprintf(stdout, "%s\n", pass);
            fflush(stdout);
            ret = OK;
        } else {
            fprintf(stderr, "Error: Unable to generate password\n");
        }
        memset(pass, 0, PASS_LEN + 1);
        free(pass);
    }

    memset(out_buf, 0, BUF_LEN);
    free(out_buf);

    return (ret);
}
