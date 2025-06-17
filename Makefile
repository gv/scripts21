# Flags for some of the stuff I build
ALL_OUTPUT := $(CURDIR)
O ?= $(ALL_OUTPUT)
R := $(ALL_OUTPUT)/release$(cf)$(vgccversion)
HERE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SRC := $(HERE)
S := $(SRC)
SHELL=/bin/bash -o pipefail
_MAKEFLAGS = -Rr
platform = $(shell uname -s)
B = $(platform:Darwin=build)$(cf)$(vgccversion)
tools0 = $(platform:Darwin=/win/tools:/Volumes/cmake-3.28.3-macos10.10-universal/CMake.app/Contents/bin:)
tools = $(tools0:Linux=)
cflags = $(cf:-a=-fsanitize=address)

# ---------- project specific options ----------

%.perfc: cov.flags="EXTRA_CFLAGS=-fprofile-arcs -ftest-coverage"
%.perf %.perfc %.perfc.g: output=$O/build.$(@:.g=)
%.perf %.perfc:
	mkdir -p $(output)
	cd $*/tools/perf && $(MAKE) O=$(output) V=1\
		NO_JEVENTS=1 NO_LIBTRACEEVENT=1 $(cov.flags)

%.perfc.g:
	cd $O/$*/tools/perf && gcov -dp $(shell find $(output) -iname '*.o')

perf.dnf:
	dnf install elfutils-devel elfutils-libelf-devel

perf-static: bzip2-1.0.6.m xz.m elfutils.m
	mkdir -p $O/static.perf
	cd linux/tools/perf &&\
		$(MAKE) O=$O/static.perf V=1 LDFLAGS="-static -L$R/lib"\
		EXTRA_CFLAGS=-I$R/include

Clang_DIR = /Volumes/clang+llvm-9.0.0-x86_64-darwin-apple
elfutils.options = --enable-maintainer-mode
binutils-gdb.options.Darwin = --disable-gold --disable-ld --enable-targets=all
binutils-gdb.options = --disable-gold --enable-targets=all\
	CFLAGS="-g -O2 -Wno-error=cast-function-type -Wno-error=stringop-truncation\
		-Wno-error=format-truncation -Wno-error=format-overflow"
binutils-gdb.envvars = MAKEINFO=:

qemu.envvars.Darwin = PKG_CONFIG=$R/bin/pkg-config
qemu6.envvars.Darwin = $(qemu.envvars.Darwin)
qemu%: options = --target-list=x86_64-softmmu --disable-docs\
	--disable-guest-agent --disable-curl\
	--disable-live-block-migration --enable-slirp
# --enable-virtfs works only on Linux
qemu%: options.Linux = --enable-gtk 

pkg-config.options = --with-internal-glib
__lldb.envvars = LLVM_DIR=$(Clang_DIR) Clang_DIR=$(Clang_DIR)
__lldb.options = -DCMAKE_CXX_COMPILER=$(Clang_DIR)/bin/clang++\
	-D CMAKE_C_COMPILER=$(Clang_DIR)/bin/clang\
	-D CMAKE_BUILD_TYPE=RelWithDebInfo\
	-DLLDB_INCLUDE_TESTS=0
swig.options += -D WITH_PCRE=OFF
# RelWithDebInfo doesn't work!
lldb.options =\
	-D CMAKE_BUILD_TYPE=RelWithDebInfo\
	-DLLDB_USE_SYSTEM_DEBUGSERVER=ON\
	-DLLDB_INCLUDE_TESTS=0\
	-DLLDB_ENABLE_PYTHON=1\
	-D CMAKE_EXE_LINKER_FLAGS=-g\
	-D CMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -Os"
# CMAKE_INSTALL_MODE requires cmake 3.22
llvm.options =\
	-D CMAKE_BUILD_TYPE=RelWithDebInfo\
	-D CMAKE_CXX_FLAGS_RELWITHDEBINFO='-Os -g -DNDEBUG'\
	-D LLVM_INCLUDE_TESTS=0\
	-D LLVM_TARGETS_TO_BUILD=X86
# Doesn't work in cmake 3.20
#	-DCMAKE_AR="ls nonsence"
clang.options = $(llvm.options)\
	-DCLANG_INCLUDE_TESTS=0
rtags.options = -D\
	LIBCLANG_LLVM_CONFIG_EXECUTABLE="$(Clang_DIR)/bin/llvm-config"\
	-D CMAKE_CXX_COMPILER="$(Clang_DIR)/bin/clang++"
qtbase.options = -extprefix "$R" -v -opensource -confirm-license\
	-qtlibinfix AndroidEmu
fuzzy_dictionary.envvars =\
 CXXFLAGS="-target x86_64-gnu-linux -v\
  -I /Library/Developer/CommandLineTools/usr/include/c++/v1\
  -I /win/third_party/release/glibc.2.7/include\
  -I /win/third_party/glibc/Kernel-headers"\
 LDFLAGS="-target x86_64-gnu-linux -v\
  -fuse-ld=/Volumes/clang+llvm-9.0.0-x86_64-darwin-apple/bin/ld.lld"
# fuzzy_dictionary.envvars = CXX="clang++ -v"
fuzzy_dictionary.targets = fuzzy_dictionary_lib
core6.options = --target x86_64-gnu-linux\
	"CPPFLAGS=-target x86_64-gnu-linux\
	-Wno-inconsistent-missing-override\
	-I /Library/Developer/CommandLineTools/usr/include/c++/v1\
	-I /win/third_party/release/glibc.2.7/include\
	-I /win/third_party/glibc/Kernel-headers"\
	"LDFLAGS=-target x86_64-gnu-linux -v\
	-fuse-ld=/Volumes/clang+llvm-9.0.0-x86_64-darwin-apple/bin/ld.lld\
	--sysroot=/win/third_party/release/glibc.2.7\
	-rtlib=compiler-rt"
core6.overrides = MAKE="make -W kodwebd/stdafx.h.gch -W\
	kdb/stdafx.h.gch"
core6.deps = $S/portable_autotools/realpath
__pdf2djvu.options = "POPPLER_CFLAGS=-I $(HERE)/../third_party/include"\
	"POPPLER_LIBS=-L $(HERE)/../third_party/lib"
pdf2djvu.overrides = -f ../pdf2djvu/Makefile
usb.options = CFLAGS="-Wno-incompatible-pointer-types -Wno-format"
keyfuzz.options = --disable-lynx
_build%evince: options=-Ddjvu=enabled -Dnautilus=false\
	-Dintrospection=false -Dgtk_doc=false -Duser_doc=false\
	-Dgspell=disabled

#
# To build with OS paths baked in:
# scl enable gcc-toolset-12 'make evince.n B=global R=/usr'
#

zsh%: options = --with-tcsetpgrp

%emacs: options = --with-tiff=no --with-xpm=no --with-gnutls=no\
	--with-jpeg=no --with-gif=no

# If I use PKG_CONFIG_LIBDIR system packages are not found
%network-manager-applet %nma1: options = -Dwwan=false -Dteam=false
%network-manager-applet %nma1:\
	envvars = PKG_CONFIG_PATH=$R/lib64/pkgconfig
libnma%: options = -Dgcr=false -Dintrospection=false -Dvapi=false

network-manager-applet.n: libnma.m

libass.n: harfbuzz.m fribidi.m freetype2.m
freetype2.m: bzip2.m zlib.m
bzip2.m:
	$(MAKE) bzip2.install_ DISABLE_MESON=disable

new-emacs.n: new-fake-manuals
%fake-manuals:
	mkdir -p $*emacs/info
	echo "Fake" > $*emacs/info/emacs
	echo "Fake" > $*emacs/info/emacs.info

noinstall.qemu make.qemu qemu6.n: pkg-config.m glib.m pixman.m
# qemu must skip meson.build
qemu8.n_: qemu8.m_
glib.m: pcre-8.45.m
aqemu.make: pkg-config.install_ glib.install_ pixman.install_

lldb.n: swig.m clang.m
clang.m: llvm.m

%ffmpeg: options = --disable-yasm
SDL%: options = -D SDL_CAMERA=0 -D SDL_DIALOG=0 -D SDL_JOYSTICK=0\
	-D SDL_HAPTIC=0 -D SDL_POWER=0 -D SDL_SENSOR=0 -D SDL_HIDAPI=0
ffmpeg.n: SDL.m

T = samba/source3

samba/source3.options = CFLAGS="-O -Wno-deprecated-declaration"

$R/samba.make.successful.log.txt: $T/Makefile $(MAKEFILE_LIST) $f
	(cd $T && $(MAKE)) 2>&1 |tee -a $@.tmp.txt
	mv -v $@.tmp.txt $@

4samba.n: zlib.m pkg-config.m

4samba.options = --without-gpgme --disable-python --without-winbind\
	--without-ads --without-ldap --disable-cups --disable-iprint\
	--without-pam --without-quotas  --without-sendfile-support --without-utmp\
	--disable-avahi --without-acl-support --without-dnsupdate\
	--without-syslog --without-automount --without-dmapi --without-fam\
	--without-libarchive --without-regedit --without-winexe\
	--without-fake-kaserver  --disable-glusterfs --disable-cephfs\
	--disable-spotlight --without-systemd --without-ad-dc --without-json

HB = /win/hb

gnutls.includes0 = -I$(HB)/Cellar/gnutls/3.6.15/include\
	-I$(HB)/Cellar/nettle/3.7.1/include\
	-I$(HB)/Cellar/libtasn1/4.16.0_1/include\
	-I$(HB)/Cellar/libidn2/2.3.0/include\
	-I$(HB)/Cellar/p11-kit/0.23.22/include/p11-kit-1

gnutls.includes = -I$(HB)/include

# These are the options for configuring+building source3/ directory
# separately - that's not possible since version 4!
hbsamba.source3.options.common = --without-winbind\
	--without-ads --without-ldap --disable-cups --disable-iprint\
	--without-pam --without-quotas  --without-sendfile-support --without-utmp\
	--disable-avahi --without-acl-support\
	--without-syslog --without-automount --without-dmapi --without-fam\
	--without-libarchive --without-regedit\
	--without-fake-kaserver  --disable-glusterfs --disable-cephfs\
	--disable-spotlight

hbsamba.source3.options = $(hbsamba.source3.options.common)\
	--without-dnsupdate

hbsamba.source3.options.4.13 = $(hbsamba.source3.options) --without-winexe

hbsamba.options.4.11 = $(hbsamba.source3.options)\
	--without-gpgme --disable-python\
	--without-systemd --without-ad-dc --without-json

hbsamba415.options = $(hbsamba.source3.options.common)\
	--without-gpgme --disable-python\
	--without-systemd --without-ad-dc --without-json

hbsamba.options = $(hbsamba.options.4.11)

YAPPDIR = $S/Parse-Yapp-1.21

# hbsamba_.n: topconfdir = $S/$*/source3
wafout = $S/$*/bin
hbsamba.n: env = PERL5LIB=$(YAPPDIR)/lib
hbsamba.n hbsamba415.n: cenv = ln -sfv /usr/lib/libreadline.dylib $(wafout) &&\
	PATH=$(HB)/bin:$(YAPPDIR):$(PATH)\
	CPPFLAGS="$(gnutls.includes)"\
	LDFLAGS="-L$(wafout)" $(env)
# If I change this to hbsamb%.n: per target vars don't work
hbsamba.n: $R/hbsamba.wafhb.successful.log.txt 
	@echo $^ is up to date

hbsamba415.n: env = PERL5LIB=$(YAPPDIR)/lib
hbsamba415.n: $R/hbsamba415.wafhb.successful.log.txt 
	@echo $^ is up to date


topconfdir = $S/$*

# $(HB)/bin to find pkg-config & it finds everything else
$S/%/bin/c4che/default_cache.py: $S/%/*/bin/waf $S/%/wscript\
		$(MAKEFILE_LIST) $f
	cd $S/$* && $(cenv) $< configure\
		-t $(topconfdir) --prefix="$R" $($*.options)

$R/%.wafhb.successful.log.txt: $S/%/*/bin/waf $S/%/wscript\
		$S/%/bin/c4che/default_cache.py $(MAKEFILE_LIST) $f
	mkdir -p $(dir $@)
	(cd $S/$* && $(env) caffeinate nice $< build -kvt $(topconfdir)) 2>&1 |\
		tee -a $@.tmp.txt
	mv $@.tmp.txt $@
	$(AFSCTOOL) -cfvvv $S/$*


# ----------- debug ----------------------------

.PHONY: make.% %.make noinstall.% %.noinstall _build.% %.n %.m

vars:
	@echo R = $R
	@echo S = $S
	@echo O = $O
	@echo MAKEFLAGS = $(MAKEFLAGS)
	@echo B = $B
	@echo X = $X
	@echo MAKE = $(MAKE)

subvars:
	$(MAKE) vars

# ----------- common rules ---------------------

AFSCTOOL.Darwin = $(HERE)/afsctool/afsctool
AFSCTOOL = $(AFSCTOOL.$(platform))
COMPRESS_AND.Linux = @
COMPRESS_AND.Darwin = $(AFSCTOOL) -cfvvv $O/$B.$* &&
COMPRESS_R_AND.Linux = @
COMPRESS_R_AND.Darwin = $(AFSCTOOL) -cfvvv $R &&
COMPRESS_AND = $(COMPRESS_AND.$(platform))
COMPRESS_R_AND = $(COMPRESS_R_AND.$(platform))

$(AFSCTOOL.Darwin): $(AFSCTOOL.Darwin).c
	gcc -o $@ $^

.PRECIOUS: $O/$B.%/Makefile $O/$B.%/build.ninja\
	%/configure %/Makefile.in %/Makefile\
	$R/%.installed.logc $R/%.make.successful.log.txt\
	$O/$B.%/%.ninja.success.logc $R/%.waf.successful.log.txt\
	$(AFSCTOOL)

$f:
	echo Force=$f

noinstall.% %.noinstall %.n:
	$(MAKE) _build.$*

_build.% %.n_: $R/%.waf.successful.log.txt $(AFSCTOOL) $f
	$(COMPRESS_AND) echo $^ is up to date	

_build.% %.n_: $O/$B.%/%.ninja.success.logc $(AFSCTOOL) $f
	$(COMPRESS_AND) echo $^ is up to date	

_build.% %.n_ %.m_: $R/%.make.successful.log.txt $(AFSCTOOL) $f
	$(COMPRESS_AND) echo $^ is up to date	

%.m:
	$(MAKE) $*.install_

%.install_: $R/%.installed.logc $(AFSCTOOL) $f
	$(COMPRESS_R_AND) echo $^ is up to date	

# Build specifically with configure/make
%.make: $(AFSCTOOL) $(MAKEFILE_LIST) $O/$B.%/Makefile
	PATH=$(tools)$(PATH) $(MAKE) $R/$*.make.successful.log.txt 
	$(COMPRESS_AND) echo $^ is up to date	


$R/%.installed.logc: $S/%/*.gyp $(MAKEFILE_LIST)
	(cd $* && GREP_OPTIONS= $($*.envvars)\
		gyp --depth=. --format=ninja-linux &&\
		ninja -vC out/Release $($*.targets)) 2>&1 |tee -a $@.tmp.txt
	mv -v $@.tmp.txt $@

$R/%.installed.logc: $O/$B.%/%.ninja.success.logc $(MAKEFILE_LIST)
	mkdir -p $(dir $@)
	(cd $O/$B.$* && PATH=$(tools)$(PATH) CMAKE_INSTALL_MODE=SYMLINK\
		ninja install) 2>&1 | tee $@.tmp.txt
	mv -v $@.tmp.txt $@

$R/%.installed.logc: $R/%.make.successful.log.txt $(MAKEFILE_LIST)
	mkdir -p $(dir $@)g
	(cd $O/$B.$* && $(MAKE) V=1 VERBOSE=1 install) 2>&1 | tee -a $@.tmp.txt
	mv -v $@.tmp.txt $@

$R/%.waf.successful.log.txt: $S/%/*/bin/waf $S/%/wscript\
		$(MAKEFILE_LIST) $f
	mkdir -p $(dir $@)
	mkdir -p $S/$B.$*
	cd $S/$B.$* && PATH=$R/bin:$(PATH) $< configure\
		-t $S/$* --prefix="$R" $($*.options)

$R/%.make.successful.log.txt: $O/$B.%/Makefile $(MAKEFILE_LIST) $f
	mkdir -p $(dir $@)
	(cd $O/$B.$* && $(MAKE) V=1 VERBOSE=1 $($*.overrides)) 2>&1 |\
		tee -a $@.tmp.txt
	mv -v $@.tmp.txt $@

$O/$B.%/Makefile: $S/%/configure $(MAKEFILE_LIST) $(deps)
	chmod +x $(dir $<)/configure
	mkdir -p $(dir $@)
	cd $(dir $@) &&\
		$($*.envvars) PATH=$(tools)$R/bin:$(PATH) ACLOCAL_PATH=$R/share/aclocal\
		$(dir $<)/configure $(options) $(options.$(platform))\
		$($*.options) $($*.options.$(platform)) --prefix="$R" 2>&1|\
		tee _configure.log\

CAFF = $(shell which caffeinate)
$O/$B.%/%.ninja.success.logc: $O/$B.%/build.ninja $(AFSCTOOL)\
	$(MAKEFILE_LIST) $f
	mkdir -p $(dir $@)
	(cd $O/$B.$* &&\
		echo "vg: Entering directory '$$(pwd)'" &&\
		PATH=$(tools)$(PATH)\
		time $(CAFF) nice ninja -d explain -vj3 ) 2>&1 |\
		tee $@.tmp.txt
	$(COMPRESS_AND) echo $^ is up to date	
	mv -v $@.tmp.txt $@

$O/$B.%/build.ninja: $S/%/meson.build $S/%/meson/meson.py\
	$(MAKEFILE_LIST)
	mkdir -p $O/$B.$*
	cd $O/$B.$* &&\
		$($*.envvars) python3 $S/$*/meson/meson.py --prefix="$R"\
		$($*.options) $(options) $S/$*

$O/$B.%/build.ninja: $S/%/meson.build $(MAKEFILE_LIST) $(DISABLE_MESON)
	mkdir -p $O/$B.$*
# If build files are present --reconfigure is mandatory, but it's an
# error to pass that when there are none.
# TODO Change in $(options) doesn't work now
	test -f $@ ||\
		$($*.envvars) $(envvars)\
		PATH=$(tools)$(PATH) CFLAGS="-I$R/include $(cflags)" python3.9\
		$S/meson/meson.py setup\
		--prefix="$R" $($*.options) $(options) $O/$B.$* $S/$* 2>&1|\
		tee $O/$B.$*/meson_.log

$O/$B.%/build.ninja: $S/%/CMakeLists.txt $(MAKEFILE_LIST)
	mkdir -p $O/$B.$*
		$($*.envvars) PATH=$(tools)$(PATH)\
		cmake -DCMAKE_INSTALL_PREFIX="$R"\
		-DCMAKE_EXPORT_COMPILE_COMMANDS=YES -D BUILD_TESTING=0\
		-D CMAKE_BUILD_TYPE=RelWithDebInfo -G Ninja $(options)$($*.options)\
		-S $(HERE)/$* -B $O/$B.$*

%.makefile_in_src: %/Makefile
	cd $(dir $^) && make --trace
#	cd $(dir $^) && make --trace install PREFIX=$R

%/Makefile: %/configure $(MAKEFILE_LIST) $(deps)
	mkdir -p $(dir $@)
	cd $(dir $@) &&\
		$($*.envvars) ACLOCAL_PATH=$R/share/aclocal ./configure\
			$(options) $($*.options) --prefix="$R" 2>&1| tee _configure.log\

%/Makefile.in: %/configure %/Makefile.am
	cd $(dir $@) &&\
		libtoolize -c -f &&\
		automake --add-missing --copy --force-missing

%/configure: %/autogen.sh
	cd $(dir $@) && NOCONFIGURE=1 ACLOCAL_PATH=$R/share/aclocal\
		bash -xe $< 2>&1 | tee autogen.log ||\
		(rm configure && false)

%/configure: %/configure.ac  $(MAKEFILE_LIST)
	cd $(dir $@) && ACLOCAL_PATH=$R/share/aclocal autoreconf -iv

%/configure: %/configure.in 
	cd $(dir $@) && autoheader -v && aclocal --verbose && autoconf -v

clean:
	rm -rfv $O/$B.elfutils $R

13:
	scl enable gcc-toolset-13 -- $(MAKE) $t vgccversion=$@
