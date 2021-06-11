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
  - unix, beos, possibly cygwin:
      ```text
      $HOME/husky/              -> huskybse/
                                -> huskylib/
                                -> smapi/
                                -> fidoconfig/
                                -> areafix/
                                -> hpt/
                                -> htick/
                                ...some other subproject
      ```
   - windows, dos, os/2 & etc:
      ```text
         d:\husky\              -> huskylib\
                                -> smapi\
                                -> fidoconf\
                                -> areafix\
                                -> hpt\
                                -> htick\
                                ...some other subproject
      ```
This can be done by cloning the git repository from GitHub:
```
    git clone https://github.com/huskyproject/hpt.git
```
Or you may download the source code archive from
```
    https://github.com/huskyproject/hpt/releases/latest
```

## Build 

### Compiling and installing with the standard Makefile and huskymak.cfg

You should prepare `huskymak.cfg` (see `huskybse`) and run (this method is for
unixes only):
```
   $ make
   $ sudo make install
```
This will also install man pages.

After you have installed the compiled files you do not need their copies in
the `hpt` directory any more. So you may delete them by running
```
    $ make distclean
```
To uninstall everything that was installed run
```
    $ sudo make uninstall
```
This will not delete the files of compiled code from the directory of the
`hpt` subproject if you did not run `make distclean`.

#### Compiling and installing documentation

You may compile and install the `hpt` manual in the following formats:
`info`, `html`, `pdf`, `plain text`, `dvi`. This should be done separately from
compiling and installing the code.

To install the manual in the `info` format you have to define `INFODIR` variable in
your `huskymak.cfg`:
```
    INFODIR=$(PREFIX)/share/info
```
To compile the manual in `html`, `plain text`, `dvi`, `pdf` formats you have to
define the corresponding variables in your `huskymak.cfg`.
```
    HTMLDIR=$(PREFIX)/share/doc/husky
    TXTDIR=$(PREFIX)/share/doc/husky
    DVIDIR=$(PREFIX)/share/doc/husky
    PDFDIR=$(PREFIX)/share/doc/husky
```
To compile and install the documentation run
```
    $ make gen-doc
    $ sudo make install-doc
```
After you have installed the compiled documentation files you do not need their
copies in the `hpt` directory any more. So you may delete them by running
```
    $ make distclean-doc
```
To uninstall all installed documentation run
```
    $ sudo make uninstall-doc
```

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

