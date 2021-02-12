/*
 * Copyright (c) 2016-2019 by John Jacob.
 * This file is licensed under the GNU General Public License, version 3.
 * http://www.gnu.org/licenses/gpl.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>              /* for isspace() */
#include <libgen.h>             /* for basename() */
#include <stdbool.h>            /* for true and false */
#include <limits.h>             /* for PATH_MAX */
#include <dirent.h>             /* for MAXNAMLEN on BSD type systems */
#include <sys/types.h>          /* for O_RDONLY */
#include <sys/stat.h>           /* for stat() */
#include <fcntl.h>              /* for open() */
#include <unistd.h>             /* for close() and getopt() */
#include <curses.h>             /* for getch(), ERR and OK */
#include <signal.h>             /* for sigaction() */
#include <math.h>               /* for log2l() */
#include <bzlib.h>              /* needs libbz2 library installed */
#include <gmp.h>                /* needs GNU MP library installed */

/*
 * DEFINITIONS
 */
#define HEX                16
#define ESC                27

#if (!defined(PATH_MAX))
    #if (defined(MAXNAMLEN))    /* BSD-derived systems have MAXNAMLEN */
        #define PATH_MAX   MAXNAMLEN
    #else
        #warning "PATH_MAX and MAXNAMLEN are both undefined, hard coding 1024"
        #define PATH_MAX   1024
    #endif
#endif

/*
 * This is sufficient to avoid most brute force attacks as of 2019. This
 * length can be increased in future to avoid future attacks with more
 * powerful computing equipment. However, note that changing this value
 * will change the password generated given the same input, and break
 * compatibility.
 */
#define PASS_LEN           29
#define SYM_TAB_LEN        sizeof(def_sym_tab)
/* This is sufficient for the input data to have good entropy. */
#define BUF_LEN            1024
/*
 * MIN_BUF_CHARS is the smallest number that satisfies the inequality
 * 2^(MIN_BUF_CHARS*8) > SYM_TAB_LEN^PASS_LEN
 */
#define MIN_BUF_CHARS      24
#define ALPHANUM_COUNT     (26 + 26 + 10)

/*
 * CONSTANTS
 */

/*
 * This is a list of password characters that are valid for the majority
 * of applications. This list is obtained from the following resource.
 * http://www.microsoft.com/resources/documentation/windows/xp/all/proddocs/en-us/windows_password_tips.mspx
 * If a particular application does not accept some characters from this list,
 * then delete those characters from the generated password before using it
 */
const char def_sym_tab[] = {
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

/*
 * GLOBAL VARIABLES
 */
char         * sym_tab       = (char *) def_sym_tab;
unsigned int   sym_tab_len   = SYM_TAB_LEN;
unsigned int   min_buf_chars = MIN_BUF_CHARS;
WINDOW       * app_win       = NULL;
bool           debug_enabled = false;

/*
 * FORWARD DECLARATIONS
 */
static void secure_exit (int return_code);

static int get_file_len (int fdesc, off_t *len)
{
    struct stat info;
    if ((len == NULL) || (fstat(fdesc, &info) != OK)) {
        return (ERR);
    }

    *len = info.st_size;
    return (OK);
}

static int read_file_data (FILE *fdesc, char *buf, off_t offset)
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

static int convert_num (char * inp_buf, int inp_len, char * out_buf,
                        int out_len)
{
    mpz_t val, quot;
    const unsigned long mod = sym_tab_len;
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
            wprintw(app_win,
                    "Error: input quenched before output generated.\n");
            return (ERR);
        }

        /* val = quot */        
        mpz_set(val, quot);
    }

    /* this should not be a big deal */
    if (mpz_cmpabs_ui(val, mod) > 0) {
        if (debug_enabled) {
            wprintw(app_win, "Warning: input buffer incompletely used.\n");
        }
    }
    
    return (OK);
}
 
/*
 * This function converts a hexadecimal value in to the equivalent character
 * representation. For example, the value 14 is converted in to the character
 * 'E'.
 */
static char hex_text (char value)
{
    unsigned char ret = (unsigned char) ERR;

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
        default: wprintw(app_win,
                         "Error: bad value %u for hex conversion.\n", value);
                 secure_exit(ret);
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
static int generate_pass (char * data, int bytes, char * pass, int len)
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
        wprintw(app_win, "Error: insufficient memory.\n");
        return (ERR);
    }
    
    memset(b16data, 0, b16len);
    for (count = 0; count < bytes; count++) {
        b16data[count * 2]       = hex_text((data[count] & 0xf0) >> 4);
        b16data[(count * 2) + 1] = hex_text(data[count] & 0x0f);
    }

    if (debug_enabled) {
        wprintw(app_win, "Info: Input hex string is %d bytes and is %s\n",
                b16len, b16data);
        fflush(stdout);
    }

    ret = convert_num(b16data, b16len, pass, len);
    memset(b16data, 0, b16len);
    free(b16data);

    return (ret);
}

static int check_history_logging (char *progname)
{
    int   ret = ERR;
    char *histignore;

    histignore = getenv("HISTIGNORE");
    if ((histignore != NULL) && (progname != NULL) &&
        (strstr(histignore, progname) != NULL)) {
        ret = OK;
    }

    return (ret);
}

static int usage (char *progname)
{
    static const char *reqd = "[REQUIRED]";
    static const char *opt = "[OPTIONAL]";
    wprintw(app_win,
            "Usage: %s [-v] [-n <offset>] [-a] [-s <code>] -f <file>\n",
            progname);
    wprintw(app_win,
            "  -f : Path of the file to generate password from. %s\n", reqd);
    wprintw(app_win,
            "  -n : Offset within the file.                     %s\n", opt);
    wprintw(app_win,
            "  -a : Generate alpha-numeric characters only.     %s\n", opt);
    wprintw(app_win,
            "  -s : Use the special character with the given ASCII\n");
    wprintw(app_win,
            "       code, in addition to alpha-numeric characters.\n");
    wprintw(app_win,
            "       This option may be repeated multiple times, and\n");
    wprintw(app_win,
            "       its presence implies \"-a\".                  %s\n", opt);
    wprintw(app_win,
            "  -v : This enables verbose output for debugging.  %s\n", opt); 
    return (OK);
}

static int process_args (int argc, char *argv[], char *fname, off_t *offset)
{
    typedef struct _special_char_list {
        char special_char;
        bool in_charset;
    } special_char_list;

    static special_char_list special_charset[] = {
        {'`', false} /* 96 */,  {'~', false}  /* 126 */,
        {'!', false} /* 33 */,  {'@', false}  /* 64 */,
        {'#', false} /* 35 */,  {'$', false}  /* 36 */,
        {'%', false} /* 37 */,  {'^', false}  /* 94 */,
        {'&', false} /* 38 */,  {'*', false}  /* 42 */,
        {'(', false} /* 40 */,  {')', false}  /* 41 */,
        {'_', false} /* 95 */,  {'+', false}  /* 43 */,
        {'-', false} /* 45 */,  {'=', false}  /* 61 */,
        {'{', false} /* 123 */, {'}', false}  /* 125 */,
        {'|', false} /* 124 */, {'[', false}  /* 91 */,
        {']', false} /* 93 */,  {'\\', false} /* 92 */,
        {':', false} /* 58 */,  {'"', false}  /* 34 */,
        {';', false} /* 59 */,  {'\'', false} /* 39 */,
        {'<', false} /* 60 */,  {'>', false}  /* 62 */,
        {'?', false} /* 63 */,  {',', false}  /* 44 */,
        {'.', false} /* 46 */,  {'/', false}  /* 47 */
    };
    char user_opt, special_char, *infile = NULL, *invptr = NULL,
         *custom_symtab = NULL;
    bool full_charset = true, found;
    int special_count = 0, i, j, ret = ERR;
    long long number;
    long double complexity;

    while ((user_opt = getopt(argc, argv, "n:s:f:av")) != -1) {
        switch (user_opt) {
            case 'f':
            infile = optarg;
            break;

            case 'n':
            if (offset) {
                invptr = NULL;
                number = strtoll(optarg, &invptr, 0);
                if ((NULL == invptr) || isspace(invptr[0]) ||
                    (invptr[0] == '\0')) {
                    *offset = number;
                } else {
                    wprintw(app_win, "Error: The offset %s is invalid.\n",
                            optarg);
                    return (ERR);
                }
            } else {
                wprintw(app_win, "An internal error has occurred.\n");
                return (ERR);
            }
            break;

            case 'a':
            full_charset = false;
            break;

            case 'v':
            debug_enabled = true;
            break;

            case 's':
            full_charset = false;
            invptr = NULL;
            special_char = (char) strtol(optarg, &invptr, 0);
            if ((NULL == invptr) || isspace(invptr[0]) ||
                (invptr[0] == '\0')) {
                found = false;
                for (i = 0;
                     i < sizeof(special_charset)/sizeof(special_char_list);
                     i++) {
                     if (special_charset[i].special_char == special_char) {
                         if (false == special_charset[i].in_charset) {
                             special_charset[i].in_charset = true;
                             special_count ++;
                         }
                         found = true;
                         if (debug_enabled) {
                             wprintw(app_win,
                                     "Debug: Using special character \"%c\" "
                                     "(\"%s\").\n", special_char, optarg);
                         }
                         break;
                     }
                }
                if (found == false) {
                    wprintw(app_win,
                            "Error: The special character \'%c\' (\"%s\") is "
                            "not supported.\n", special_char, optarg);
                    return (ERR);
                }
            } else {
                wprintw(app_win,
                        "Error: The special character \"%s\" is not valid.\n",
                        optarg);
                return (ERR);
            }
            break;
            
            default:
            return (ERR);
        }
    }

    if (NULL == infile) {
        wprintw(app_win,
                "Error: Data file to generate password is not specified.\n");
    } else {
        if (false == full_charset) {
            custom_symtab = calloc(ALPHANUM_COUNT + special_count, 1);
            if (NULL == custom_symtab) {
                wprintw(app_win, "Error: Insufficient memory.\n");
            } else {
                for (i = 0; i < ALPHANUM_COUNT; i++) {
                    custom_symtab[i] = def_sym_tab[i];
                }
                if (special_count) {
                    j = 0;
                    for (i = 0;
                        i < sizeof(special_charset)/sizeof(special_char_list);
                        i++) {
                        if ((true == special_charset[i].in_charset) &&
                            (j < special_count)) {
                            custom_symtab[ALPHANUM_COUNT + j]
                                = special_charset[i].special_char;
                            j++;
                        }
                    }
                    if (j != special_count) {
                        free(custom_symtab);
                        wprintw(app_win,
                                "Error: An internal error has occurred.\n");
                    } else {
                        ret = OK;
                    }
                } else {
                    ret = OK;
                }
                /*
                 * Now we need to adjust min_buf_chars using the inequality:
                 *   2^(min_buf_chars*8) > SYM_TAB_LEN^PASS_LEN
                 * Or, in other words:
                 *   min_buf_chars > log2(SYM_TAB_LEN^PASS_LEN)/8
                 * Simplifying,
                 *   min_buf_chars > (PASS_LEN * log2(SYM_TAB_LEN))/8
                 * Optimizing, since (PASS_LEN / 8) = 3.5,
                 * (but let the compiler do this)
                 *   min_buf_chars = 3.5 * log2(SYM_TAB_LEN)
                 */
                if (OK == ret) {
                    complexity
                        = log2l((long double) (ALPHANUM_COUNT + special_count));
                    complexity *= (long double) (PASS_LEN / 8.0);
                    complexity = ceil(complexity);
                    min_buf_chars = (unsigned int) complexity;
                    if (debug_enabled) {
                        wprintw(app_win,
                                "Debug: For symbol table length %u (special "
                                "count %u), minimum buffer chars is %u.\n",
                                ALPHANUM_COUNT + special_count, special_count,
                                min_buf_chars);
                    }
                    /* Update the global variables */
                    sym_tab = custom_symtab;
                    sym_tab_len = ALPHANUM_COUNT + special_count;
                }
            }
        } else {
            ret = OK;
        }
    }

    if (OK == ret) {
        strncpy(fname, infile, PATH_MAX);
    }

    return (ret);
}

static void secure_exit (int return_code)
{
    wprintw(app_win, "\n\nPress any key to continue...");
    (void) getch();                      /* wait for the user to press a key */
    endwin();
    fprintf(stderr, "%c[2J%c[1;1H",      /* clear the users' terminal screen */
            (char) ESC, (char) ESC);
    if (sym_tab != def_sym_tab) {
        memset(sym_tab, 0, sym_tab_len); /* clear the buffer if allocated */
        free(sym_tab);                   /* free it if it was allocated */
    }
    exit(return_code);                   /* this function does not return */
}

static int term_setup (void)
{
    int ret = ERR;

    if (NULL != (app_win = initscr())) {
        wtimeout(app_win, -1);
        notimeout(app_win, false);
        nodelay(app_win, false);
        ret = OK;        
    }
    return (ret);
}

/*
 * Remember to use the shell HISTIGNORE environment variable to prevent the
 * command line from being remembered in the shell history!
 */
int main (int argc, char *argv[])
{
    FILE *inp = NULL;
    off_t len = 0, offset = 0;
    unsigned int out_len, fd, ret = ERR;
    char *in_buf, *out_buf, *pass, fname[PATH_MAX+1];

    if (OK != term_setup()) {
        fprintf(stderr,
                "%c[2J%c[1;1HError: Unable to initialize terminal settings. "
                "Unsupported terminal type.\n", (char) ESC, (char) ESC);
        exit(ret);
    }

    strncpy(fname, basename(argv[0]), PATH_MAX);

    if (OK != check_history_logging(fname)) {
        wprintw(app_win,
                "Error: Use \'export HISTIGNORE=\"*%s*\"\' to direct the "
                "shell to forget this command.\n", fname);
        secure_exit(ret);
    }

    if (OK != process_args(argc, argv, fname, &offset)) {
        usage(fname);
        secure_exit(ret);
    }

    fd = open(fname, O_RDONLY, 0);
    if (fd == ERR) {
        wprintw(app_win, "Error: Unable to open file %s.\n", fname);
        memset(fname, 0, PATH_MAX);
        secure_exit(1);
    }

    if (get_file_len(fd, &len) != OK) {
        wprintw(app_win, "Error: Unable to determine the attributes of the "
                " file %s. Please verify permissions.\n", fname);
        close(fd);
        secure_exit(ret);
    }

    inp = fdopen(fd, "rb");
    if (inp == NULL) {
        wprintw(app_win, "Error: Unable to stream file %s.\n", fname);
        close(fd);
        secure_exit(ret);
    }

    /* We do not need the filename any more. Clear it. */
    memset(fname, 0, PATH_MAX);

    if ((signed) offset < 0) {
        wprintw(app_win, "Error: Negative offset (%d) specified.\n", offset);
        fclose(inp);
        close(fd);
        secure_exit(ret);
    }

    if (((offset + BUF_LEN) < BUF_LEN ) || /* wrapped */
        (len < (offset + BUF_LEN))) {
        wprintw(app_win, "Error: File too small or offset too large.\n");
        fclose(inp);
        close(fd);
        secure_exit(ret);
    }

    in_buf = malloc(BUF_LEN);
    if (in_buf == NULL) {
        wprintw(app_win, "Error: Insufficient memory.\n");
        fclose(inp);
        close(fd);
        secure_exit(ret);
    }

    if (read_file_data(inp, in_buf, offset) != OK) {
        wprintw(app_win, "Error: Unable to read from file.\n");
        free(in_buf);
        fclose(inp);
        close(fd);
        secure_exit(ret);
    }

    /*
     * Now that we have read the file data, we don't need the file handle
     * any more
     */
    fclose(inp);
    close(fd);

    out_buf = malloc(BUF_LEN);
    if (out_buf == NULL) {
        wprintw(app_win, "Error: Insufficient memory.\n");
        free(in_buf);
        secure_exit(ret);
    }

    if (compress_data((char *)in_buf, (char *)out_buf, &out_len) != OK) {
        wprintw(app_win, "Error: Compression failure.\n");
        free(in_buf);
        free(out_buf);
        secure_exit(ret);
    }
    
    if (debug_enabled) {
        wprintw(app_win, "Debug: Compression ratio is %d:%d.\n", BUF_LEN,
                out_len);
    }

    if (out_len < min_buf_chars) {
        wprintw(app_win, "Error: Input file data has insufficient entropy.\n");
        free(in_buf);
        free(out_buf);
        secure_exit(ret);
    } else if (out_len >= BUF_LEN) {
        /* input data is incompressible, so let us use it directly */
        memset(out_buf, 0, BUF_LEN);
        free(out_buf);
        out_buf = in_buf;
        in_buf  = NULL;
        out_len = BUF_LEN;
    } else { /* (out_len >= min_buf_chars) && (out_len < BUF_LEN) */
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
        wprintw(app_win, "Error: Insufficient memory.\n");
    } else {
        memset(pass, 0, PASS_LEN + 1);
        if (generate_pass(out_buf, out_len,
                          pass, PASS_LEN) == OK) {
            wprintw(app_win, "Password: %s\n", pass);
            ret = OK;
        } else {
            wprintw(app_win, "Error: Unable to generate password.\n");
        }
        memset(pass, 0, PASS_LEN + 1);
        free(pass);
    }

    memset(out_buf, 0, BUF_LEN);
    free(out_buf);
    
    secure_exit(ret);

    /* this line is never executed. */
    return (ret);
}
