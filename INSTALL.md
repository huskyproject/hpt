# Instruction to build hpt

Please read the files (especially README.Makefiles) in the
husky-common (huskybse) package FIRST!

## Table of Contents
- [Prebuild](#prebuild)
- [Build](#build)
  - [Compiling and installing with the standard Makefile and huskymak.cfg](#compiling-and-installing-with-the-standard-makefile-and-huskymakcfg)
  - [Compiling with the Legacy Makefiles](#compiling-with-the-legacy-makefiles)
  - [Compiling and installing using Cmake](#compiling-and-installing-using-cmake)
- [Afterbuild actions](#afterbuild-actions)

## Prebuild

- Put the hpt package in the directory where the other packages of fido
  husky reside:
   
  - unix, beos, possible cygwin:
      ```text
      /usr/src/packages/        -> huskybse/
                                -> huskylib/
                                -> smapi/
                                -> fidoconfig/
                                -> hpt/
                                -> htick/
                                ...some other
      ```
   - windows, dos, os/2 & etc:
      ```text
         d:\husky\              -> huskylib\
                                -> smapi\
                                -> fidoconf\
                                -> hpt\
                                -> htick\
                                ...some other
      ```
## Build 

### Compiling and installing with the standard Makefile and huskymak.cfg

See huskybse/INSTALL.asciidoc

### Compiling with the Legacy Makefiles

unix:
```sh
   $ make -f makefile.lnx
   $ make -f makefile.lnx install
```
dos:
```sh
   d:\husky\hpt>make -f makefile.djg
```
 ### Compiling and installing using Cmake
 
- Run CMake to configure the build tree.
```sh
      $ cmake -H. -Bbuild -DBUILD_SHARED_LIBS=OFF
```
  This will prepare to build hpt using static libraries. If you want to build
  hpt using dynamic libraries, then you have to run
```sh
      $ cmake -H. -Bbuild
```
  Be shure to build all Husky projects the same way, either statically or
  dynamically.
- Afterwards, generated files can be used to compile the project.
   ```sh
      $ cmake --build build
   ```
- Make distrib rpm, deb,tgz (optional)
   ```sh
      $ cpack -G RPM --config build/CPackConfig.cmake
      $ cpack -G DEB --config build/CPackConfig.cmake
      $ cpack -G TGZ --config build/CPackConfig.cmake
   ```

- Install the built files (optional).
   ```sh
      $ cmake --build build --target install
   ```
## Afterbuild actions

- (For UNIXes only) Ensure /usr/local/lib/ is in /etc/ld.so.conf
- (For UNIXes only) Execute ldconfig as root

You're ready. Now you can install software which uses hpt.

