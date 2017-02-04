# Version
VERSION = 17.2

# Path Locations
USR_INC   = /usr/include
USR_LIB   = /usr/lib/
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
         -I${USR_INC}/freetype2 \
         -I${USR_INC}/libsoup-2.4 \
         -I${USR_INC}/glib-2.0 \
         -I${USR_LIB}/glib-2.0/include

# Webkit and GTK library flags
GTKLIB = -lwebkit2gtk-4.0 \
         -lgtk-3 \
         -lgdk-3 \
         -lpangocairo-1.0 \
         -latk-1.0 \
         -lcairo \
         -lgdk_pixbuf-2.0 \
         -lpangoft2-1.0 \
         -lpango-1.0 \
         -lfontconfig \
         -lfreetype \
         -lsoup-2.4 \
         -lgio-2.0 \
         -lgobject-2.0 \
         -ljavascriptcoregtk-4.0 \
         -lglib-2.0

# Other includes
INCS = -I. -I/usr/include ${GTKINC}

# Other libraries
LIBS = -L/usr/lib -lc -lX11 ${GTKLIB} -lgthread-2.0

# Flags
CFLAGS = -std=c99 \
         -O2 \
         -pedantic \
         -Wall \
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


all: options sighte

options:
	@echo sighte build options:
	@echo "CFLAGS  = ${CFLAGS}"
	@echo "LIBS    = ${LIBS}"
	@echo "CC      = ${CC}"

.c.o:
	@echo CC $<
	@${CC} -c ${CFLAGS} $<

sighte: ${OBJ}
	@echo CC -o $@
	@${CC} -o $@ sighte.o ${LIBS}

clean:
	@echo cleaning
	@rm -f sighte sighte.o sighte-${VERSION}.tar.gz

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
