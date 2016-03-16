# gen-pass
gen-pass is a complex password generator for Unix-like systems. As input, it takes a file and optional offset, and it uses this information to generate a complex password. The advantage of this method is that it is possible to regenerate the EXACT same password again using the same file and offset. The file could be a binary such as an executable, photograph, music file or movie. It could be a file publicly available on the web, such as wireshark version 2.0.1 for Win64.

Usage: gen_pass <file> <offset>
gen_pass must be invoked with the shell environment variable HISTIGNORE set so that the command being entered will not be available in the shell's history.
