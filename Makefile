# Version
VERSION = `date +%y.%m`

# If unable to grab the version, default to N/A
ifndef VERSION
    VERSION = "n/a"
endif

#
# Variables to handle debug modes
#
DEBUG_MODE_OFF   = 0
DEBUG_MODE_ON    = 1

#
# Variables to handle verbose debug output messages modes
#
VERBOSE_MODE_OFF = 0
VERBOSE_MODE_ON  = 1

# Path Locations
USR_INC   = /usr/include
GLIB_INC  = `pkg-config --cflags glib-2.0`
PREFIX    = /usr/local
MANPREFIX = ${PREFIX}/share/man

# Webkit and GTK Include paths
GTKINC = -pthread \
         -I${USR_INC}/webkitgtk-4.0 \
         -I${USR_INC}/gtk-3.0 \
         -I${USR_INC}/gio-unix-2.0 \
         -I${USR_INC}/cairo \
         -I${USR_INC}/pango-1.0 \
         -I${USR_INC}/atk-1.0 \
         -I${USR_INC}/gdk-pixbuf-2.0 \
         -I${USR_INC}/libsoup-2.4 \
         ${GLIB_INC}

# Webkit and GTK library flags
GTKLIB = -lwebkit2gtk-4.0 \
         -lgtk-3 \
         -lgdk-3 \
         -ljavascriptcoregtk-4.0 \
         -lgio-2.0 \
         -lglib-2.0 \
         -lgobject-2.0 \
         -lsoup-2.4

# Other includes
INCS = -I. -I/usr/include ${GTKINC}

# Other libraries
LIBS = -L/usr/lib -lX11 ${GTKLIB}

# Flags
CFLAGS = -std=c99 \
         -fpic \
         -Wall \
         -Wextra \
         -Wpedantic \
         -Wno-missing-braces\
         -Wformat=2 \
         -Wformat-signedness \
         -Wnull-dereference \
         -Winit-self \
         -Wmissing-include-dirs \
         -Wshift-overflow=2 \
         -Wswitch-default \
         -Wswitch-enum \
         -Wunused-const-variable=2 \
         -Wuninitialized \
         -Wunknown-pragmas \
         -Wstrict-overflow=5 \
         -Warray-bounds=2 \
         -Wduplicated-cond \
         -Wfloat-equal \
         -Wundef \
         -Wshadow \
         -Wbad-function-cast \
         -Wcast-qual \
         -Wcast-align \
         -Wwrite-strings \
         -Wconversion \
         -Wjump-misses-init \
         -Wlogical-op \
         -Waggregate-return \
         -Wcast-align \
         -Wstrict-prototypes \
         -Wold-style-definition \
         -Wmissing-prototypes \
         -Wmissing-declarations \
         -Wpacked \
         -Wredundant-decls \
         -Wnested-externs \
         -Winline \
         -Winvalid-pch \
         -Wstack-protector \
         ${INCS} \
         -DVERSION=\"${VERSION}\" \
         -D_DEFAULT_SOURCE

# Compiler
CC = cc

# Headers
HDR = sighte.h

# C sources
SRC = sighte.c

# C objects
OBJ = ${SRC:.c=.o}


#
# Makefile options
#


# State the "phony" targets
.PHONY: all options clean dist install uninstall


all: clean release

options:
	@echo sighte build options:
	@echo "CFLAGS       = ${CFLAGS}"
	@echo "LIBS         = ${LIBS}"
	@echo "CC           = ${CC}"

release: options
	@echo "DEBUG_MODE   = ${DEBUG_MODE_OFF}"
	@echo "VERBOSE_MODE = ${VERBOSE_MODE_OFF}"
	@echo Building $@ version...
	@${CC} -s ${SRC} ${CFLAGS} -D DEBUG_MODE=${DEBUG_MODE_OFF} \
	  -D VERBOSE_MODE=${VERBOSE_MODE_OFF} -o sighte ${LIBS}

staging: options
	@echo "DEBUG_MODE   = ${DEBUG_MODE_ON}"
	@echo "VERBOSE_MODE = ${VERBOSE_MODE_OFF}"
	@echo Building $@ version...
	@${CC} -g ${SRC} ${CFLAGS} -D DEBUG_MODE=${DEBUG_MODE_ON} \
          -D VERBOSE_MODE=${VERBOSE_MODE_OFF} -o sighte ${LIBS}

debug:  options
	@echo "DEBUG_MODE   = ${DEBUG_MODE_ON}"
	@echo "VERBOSE_MODE = ${VERBOSE_MODE_ON}"
	@echo Building $@ version...
	@${CC} -g ${SRC} ${CFLAGS} -D DEBUG_MODE=${DEBUG_MODE_ON} \
          -D VERBOSE_MODE=${VERBOSE_MODE_ON} -o sighte ${LIBS}

clean:
	@echo Cleaning away old build...
	@rm -f debug sighte sighte.o sighte-${VERSION}.tar.gz

dist: clean
	@echo creating dist tarball
	@mkdir -p sighte-${VERSION}
	@cp -R Makefile LICENSE README.md sighte.png sighte.1 ${SRC} ${HDR} sighte-${VERSION}
	@tar -cf sighte-${VERSION}.tar sighte-${VERSION}
	@gzip sighte-${VERSION}.tar
	@rm -rf sighte-${VERSION}

install: all
	@echo installing executable file to ${DESTDIR}${PREFIX}/bin
	@mkdir -p ${DESTDIR}${PREFIX}/bin
	@cp -f sighte ${DESTDIR}${PREFIX}/bin
	@chmod 755 ${DESTDIR}${PREFIX}/bin/sighte
	@echo installing manual page to ${DESTDIR}${MANPREFIX}/man1
	@mkdir -p ${DESTDIR}${MANPREFIX}/man1
	@sed "s/VERSION/${VERSION}/g" < sighte.1 > ${DESTDIR}${MANPREFIX}/man1/sighte.1
	@chmod 644 ${DESTDIR}${MANPREFIX}/man1/sighte.1

uninstall:
	@echo removing executable file from ${DESTDIR}${PREFIX}/bin
	@rm -f ${DESTDIR}${PREFIX}/bin/sighte
	@echo removing manual page from ${DESTDIR}${MANPREFIX}/man1
	@rm -f ${DESTDIR}${MANPREFIX}/man1/sighte.1
