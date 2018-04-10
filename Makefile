PREFIX    = /usr/local
MANPREFIX = ${PREFIX}/share/man

# State the "phony" targets
.PHONY: all options clean dist install uninstall


all: clean release

mesonify:
	@meson sighte

release: mesonify
	@ninja -C ./sighte release
	@cp ./sighte/release release
	@rm -rf ./sighte
	@mv release sighte

staging: mesonify
	@ninja -C ./sighte staging
	@cp ./sighte/staging staging
	@rm -rf ./sighte

debug: mesonify
	@ninja -C ./sighte debug
	@cp ./sighte/debug debug
	@rm -rf ./sighte

clean:
	@echo Cleaning away old build...
	@rm -rf debug staging sighte sighte-${VERSION}.tar.gz

dist: clean
	@echo creating dist tarball
	@mkdir -p sighte-${VERSION}
	@cp * sighte-${VERSION}
	@tar -cf sighte-${VERSION}.tar sighte-${VERSION}
	@gzip sighte-${VERSION}.tar
	@rm -rf sighte-${VERSION}

install: all
	@echo installing executable file to ${PREFIX}/bin
	@mkdir -p ${PREFIX}/bin
	@cp -f sighte ${PREFIX}/bin
	@chmod 755 ${PREFIX}/bin/sighte
	@echo installing manual page to ${MANPREFIX}/man1
	@mkdir -p ${MANPREFIX}/man1
	@sed "s/VERSION/${VERSION}/g" < sighte.1 > ${MANPREFIX}/man1/sighte.1
	@chmod 644 ${MANPREFIX}/man1/sighte.1

uninstall:
	@echo removing executable file from ${PREFIX}/bin
	@rm -f ${PREFIX}/bin/sighte
	@echo removing manual page from ${MANPREFIX}/man1
	@rm -f ${MANPREFIX}/man1/sighte.1
