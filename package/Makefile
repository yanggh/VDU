
install:
	if [ ! -d "/usr/local/etc/vdu" ]; then mkdir "/usr/local/etc/vdu"; fi
	if [ ! -d "/usr/local/bin" ]; then mkdir -p "/usr/local/bin"; fi
	if [ ! -d "/usr/local/lib" ]; then mkdir -p "/usr/local/lib"; fi
	if [ ! -d "/usr/local/etc/software" ]; then mkdir -p "/usr/local/etc/software"; fi
	cp -f etc/*  /usr/local/etc/vdu/
	cp -f vdu.yaml /usr/local/etc/software/vdu.yaml
	cp -f bin/vdu /usr/local/bin/

update:
	cp -f bin/vdu /usr/local/bin/
	cp -f vdu.yaml /usr/local/etc/software/vdu.yaml

uninstall:
	rm -f  /usr/local/bin/vdu
	rm -rf /usr/local/etc/vdu
	rm -f  /usr/local/etc/software/vdu.yaml

