# gen-pass
gen-pass is a complex password generator for Unix-like systems. As input, it takes a file and optional offset, and it uses this information to generate a complex password. The advantage of this method is that it is possible to regenerate the EXACT same password again using the same file and offset. The file could be a binary such as an executable, photograph, music file or movie. It could be a file publicly available on the web, such as wireshark binary version 2.0.1 for Win64.

```
Usage: gen_pass [-v] [-n <offset>] [-a] [-s <code>] <-f <file>|-r>
  -f : Path of the file to generate password from. [REQUIRED]
  -r : Use /dev/urandom instead of a file.         [REQUIRED]
         .. One of -f and -r are required, but both
         .. of these options can't be used together.
  -n : Offset within the file.                     [OPTIONAL]
         .. This option can only be used with -f.
  -a : Generate alpha-numeric characters only.     [OPTIONAL]
  -s : Use the special character with the given ASCII
       code, in addition to alpha-numeric characters.
       This option may be repeated multiple times, and
       its presence implies "-a".                  [OPTIONAL]
  -v : This enables verbose output for debugging.  [OPTIONAL]
```

The "-a" option can be used to generate a password with alphanumeric characters only. Such a password will have less entropy than a password with alphanumeric and special characters. The "-s" option allows the generation of a password with alphanumeric characters and a special character specified by numeric ASCII code. This option can be used multiple times to add multiple special characters to the password. This is useful for websites that allow a certain restricted set of special characters in addition to alphanumeric characters in passwords. The complete set of special characters that can be added by using the "-s" option are shown below.
```
! 33   " 34   # 35   $ 36   % 37   & 38   ' 39   ( 40   ) 41   * 42   + 43
, 44   - 45   . 46   / 47   : 58   ; 59   < 60   = 61   > 62   ? 63   @ 64
[ 91   \ 92   ] 93   ^ 94   _ 95   ` 96   { 123  | 124  } 125  ~ 126
```

gen_pass must be invoked with the shell environment variable HISTIGNORE set so that the command being entered will not be available in the shell's history.

Compiling: gen_pass uses libbz2, libgmp and libcurses, in addition to the standard math library. Compile gen_pass with some variation of "gcc gen_pass.c -lm -lcurses -lbz2 -lgmp -o gen_pass". gen_pass has been tested on Linux and macOS.

