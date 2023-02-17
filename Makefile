# Flags for some of the stuff I build
ALL_OUTPUT := $(CURDIR)
O ?= $(ALL_OUTPUT)
R := $(ALL_OUTPUT)/release
HERE := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SRC := $(HERE)
S := $(SRC)
SHELL=/bin/bash -o pipefail
MAKEFLAGS = -Rr
b0 = $(shell uname -s)
B = $(b0:Darwin=build)

# ---------- project specific options ----------

make_perf: make.bzip2-1.0.6 make.xz make.elfutils
	mkdir -p $O/build.perf
	cd linux/tools/perf &&\
		$(MAKE) O=$O/build.perf V=1 LDFLAGS="-static -L$R/lib"\
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
qemu.options = --target-list=x86_64-softmmu --disable-docs\
	--disable-guest-agent --disable-curl\
	--disable-live-block-migration
qemu.options.Linux = --enable-gtk
qemu6.options = $(qemu.options)
pkg-config.options = --with-internal-glib
__lldb.envvars = LLVM_DIR=$(Clang_DIR) Clang_DIR=$(Clang_DIR)
__lldb.options = -DCMAKE_CXX_COMPILER=$(Clang_DIR)/bin/clang++\
	-D CMAKE_C_COMPILER=$(Clang_DIR)/bin/clang\
	-D CMAKE_BUILD_TYPE=RelWithDebInfo\
	-DLLDB_INCLUDE_TESTS=0
swig.options0 = --without-pcre --disable-ccache
swig.options = -DPCRE_REQUIRED_ARG=
# RelWithDebInfo doesn't work!
lldb.options =\
	-D CMAKE_BUILD_TYPE=RelWithDebInfo\
	-DLLDB_USE_SYSTEM_DEBUGSERVER=ON\
	-DLLDB_INCLUDE_TESTS=0\
	-D CMAKE_EXE_LINKER_FLAGS=-g\
	-D CMAKE_CXX_FLAGS=-g
llvm.options =\
	-D CMAKE_BUILD_TYPE=RelWithDebInfo\
	-DLLVM_INCLUDE_TESTS=0
clang.options =\
	-DCMAKE_BUILD_TYPE=RELWITHDEBINFO\
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
emacs.options=--with-tiff=no --with-xpm=no --with-gnutls=no\
	--with-jpeg=no --with-gif=no

noinstall.qemu make.qemu qemu6.n: pkg-config.m glib.m pixman.m

lldb.n: swig.m clang.m

clang.m: llvm.m

aqemu.make: pkg-config.install_ glib.install_ pixman.install_

T = samba/source3

samba/source3.options = CFLAGS="-O -Wno-deprecated-declaration"

$R/samba.make.successful.log.txt: $T/Makefile $(MAKEFILE_LIST) $f
	(cd $T && $(MAKE)) 2>&1 |tee $@.tmp.txt
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
		tee $@.tmp.txt
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

subvars:
	$(MAKE) vars

# ----------- common rules ---------------------

AFSCTOOL.Darwin = $(HERE)/afsctool/afsctool
AFSCTOOL = $(AFSCTOOL.$(b0))

$(AFSCTOOL.Darwin): $(AFSCTOOL.Darwin).c
	gcc -o $@ $^

.PRECIOUS: $O/$B.%/Makefile $O/$B.%/build.ninja\
	%/configure %/Makefile.in\
	$R/%.install.successful.log.txt $R/%.make.successful.log.txt\
	$R/%.ninja.successful.log.txt $R/%.waf.successful.log.txt\
	$(AFSCTOOL)

$f:
	echo Force=$f

noinstall.% %.noinstall %.n:
	$(MAKE) _build.$*

_build.% %.n_: $R/%.waf.successful.log.txt $(AFSCTOOL) $f
	$(AFSCTOOL) -cfvvv $O/$B.$*
	@echo $^ is up to date	

_build.% %.n_: $R/%.ninja.successful.log.txt $(AFSCTOOL) $f
	$(AFSCTOOL) -cfvvv $O/$B.$*
	@echo $^ is up to date	

_build.% %.n_ %.m_: $R/%.make.successful.log.txt $(AFSCTOOL) $f
	$(AFSCTOOL) -cfvvv $O/$B.$*
	@echo $^ is up to date	

%.m:
	$(MAKE) $*.install_

%.install_: $R/%.install.successful.log.txt $(AFSCTOOL)
	$(AFSCTOOL) -cfvvv $R
	@echo $^ is up to date	

# Build specifically with configure/make
%.make: $(AFSCTOOL) $(MAKEFILE_LIST) $O/$B.%/Makefile
	$(MAKE) $R/$*.make.successful.log.txt 
	$(AFSCTOOL) -cfvvv $O/$B.$*


$R/%.install.successful.log.txt: $S/%/*.gyp $(MAKEFILE_LIST)
	(cd $* && GREP_OPTIONS= $($*.envvars)\
		gyp --depth=. --format=ninja-linux &&\
		ninja -vC out/Release $($*.targets)) 2>&1 |tee $@.tmp.txt
	mv -v $@.tmp.txt $@

$R/%.install.successful.log.txt: $R/%.ninja.successful.log.txt $(MAKEFILE_LIST)
	mkdir -p $(dir $@)
	(cd $O/$B.$* && ninja install) 2>&1 | tee $@.tmp.txt
	mv -v $@.tmp.txt $@

$R/%.install.successful.log.txt: $R/%.make.successful.log.txt $(MAKEFILE_LIST)
	mkdir -p $(dir $@)g
	(cd $O/$B.$* && $(MAKE) V=1 VERBOSE=1 install) 2>&1 | tee $@.tmp.txt
	mv -v $@.tmp.txt $@

$R/%.waf.successful.log.txt: $S/%/*/bin/waf $S/%/wscript\
		$(MAKEFILE_LIST) $f
	mkdir -p $(dir $@)
	mkdir -p $S/$B.$*
	cd $S/$B.$* && PATH=$R/bin:$(PATH) $< configure\
		-t $S/$* --prefix="$R" $($*.options)

CAFF = $(shell which caffeinate)
$R/%.ninja.successful.log.txt: $O/$B.%/build.ninja $(AFSCTOOL)\
	$(MAKEFILE_LIST) $f
	mkdir -p $(dir $@)
	(cd $O/$B.$* && time $(CAFF) nice ninja -d explain -vj3 ) 2>&1 |\
		tee $@.tmp.txt
	$(AFSCTOOL) -cfvvv $O/$B.$*
	mv -v $@.tmp.txt $@

$R/%.make.successful.log.txt: $O/$B.%/Makefile $(MAKEFILE_LIST) $f
	mkdir -p $(dir $@)
	(cd $O/$B.$* && $(MAKE) V=1 VERBOSE=1 $($*.overrides)) 2>&1 |\
		tee $@.tmp.txt
	mv -v $@.tmp.txt $@

$O/$B.%/Makefile: $S/%/configure $(MAKEFILE_LIST) $(deps)
	chmod +x $(dir $<)/configure
	mkdir -p $(dir $@)
	cd $(dir $@) &&\
		$($*.envvars) $(dir $<)/configure $(options)\
			$($*.options) $($*.options.$(b0)) --prefix="$R" 2>&1|\
			tee _configure.log\

$O/$B.%/build.ninja: $S/%/meson.build $S/%/meson/meson.py $(MAKEFILE_LIST)
	mkdir -p $O/$B.$*
	cd $O/$B.$* &&\
		$($*.envvars) python3 $S/$*/meson/meson.py --prefix="$R"\
		$($*.options) $S/$*

$O/$B.%/build.ninja: $S/%/meson.build $(MAKEFILE_LIST)
	mkdir -p $O/$B.$*
	cd $O/$B.$* &&\
		$($*.envvars) CFLAGS=-I$R/include python3 $S/meson/meson.py\
		--prefix="$R" $($*.options) $S/$*

$O/$B.%/build.ninja: $S/%/CMakeLists.txt $(MAKEFILE_LIST)
	mkdir -p $O/$B.$*
	cd $O/$B.$* &&\
		$($*.envvars) cmake -DCMAKE_INSTALL_PREFIX="$R"\
		-DCMAKE_EXPORT_COMPILE_COMMANDS=YES -D BUILD_TESTING=0\
		-D CMAKE_BUILD_TYPE=RelWithDebInfo -G Ninja $($*.options)\
		$(HERE)/$*

makefile_in_src.%: %/Makefile
	cd $(dir $^) && make --trace
	cd $(dir $^) && make --trace install PREFIX=$R

%/Makefile: %/configure $(MAKEFILE_LIST) $(deps)
	mkdir -p $(dir $@)
	cd $(dir $@) &&\
		$($*.envvars) ./configure\
			$($*.options) --prefix="$R" 2>&1| tee _configure.log\

%/Makefile.in: %/configure %/Makefile.am 
	cd $(dir $@) &&\
		libtoolize -c -f &&\
		automake --add-missing --copy --force-missing

%/configure: %/autogen.sh_
	cd $(dir $@) && bash $< 2>&1 | tee autogen.log

%/configure: %/configure.ac 
	cd $(dir $@) && autoreconf -iv

%/configure: %/configure.in 
	cd $(dir $@) && autoheader -v && aclocal --verbose && autoconf -v

clean:
	rm -rfv $O/$B.elfutils $R

