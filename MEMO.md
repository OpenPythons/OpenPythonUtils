# firmware build
`sudo apt-get install build-essential gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf`

# java build (on windows)
1. clone `unicorn`
2. create consts for `bindings/java`
3. copy jni.h, jni_md.h to `include`
4. run javah tool (check Makefile or .make?)
5. open solution, upgrade platform tools
6. remove `UNICORN_HAS_ARM64;UNICORN_HAS_M68K;UNICORN_HAS_MIPS;UNICORN_HAS_MIPS64;UNICORN_HAS_MIPSEL;UNICORN_HAS_MIPS64EL;UNICORN_HAS_SPARC;UNICORN_HAS_X86`
   and keep `UNICORN_HAS_ARM`, `WIN32_LEAN_AND_MEAN` (almost end-of-line)
7. drag `bindings/java/unicorn_Unicorn*` files to unicorn project
8. build (Release Win32 and x64)
9. Copy dll; done!
   - filename pattern: `UmpOcMod-1.0.0-unicorn-1.0.2-arm-native.64.dll`
   - easy pattern: `unicron_x64.dll` or `unicorn_win32.dll`

# java build (on linux)
1. just build
2. Copy so; done!
