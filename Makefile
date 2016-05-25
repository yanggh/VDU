

VER = $(shell cat package/vdu-info.yaml | grep " version:" | cut -b 12-15)
BUILD   = $(shell git log | grep -cE 'Author:')
BUILDSHA = $(shell git rev-parse --short HEAD)

BSTR = $(shell printf %03d $(BUILD))

ALL: package

build:
	make -C src

clean:
	make -C src clean
	rm -f package/*.tar.gz

package: src/vdu
	if [ ! -d "package/bin" ]; then mkdir -p "package/bin"; fi
	if [ ! -d "package/lib" ]; then mkdir -p "package/lib"; fi
	if [ ! -d "package/etc" ]; then mkdir -p "package/etc"; fi
	cp src/vdu package/bin/
	cp etc/* package/etc/
	awk '($$2== "BUILDSTR") gsub("BUILDSTR","$(BSTR)")' package/vdu-info.yaml > package/vdu.yaml
	cd package && tar cpfz vdu-$(VER).$(BSTR).tar.gz bin etc lib  Makefile vdu.yaml


