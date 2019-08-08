all: ssh-agent-noasync.js

ssh-agent-noasync.js: ../chrome/ssh-agent.js
	$(CC) -Dawait='' -Dasync='' -nostdinc -C -E -x c ../chrome/ssh-agent.js -o - | grep -v '^# ' > ssh-agent-noasync.js.new
	mv ssh-agent-noasync.js.new ssh-agent-noasync.js

softokn3-pkcs11.so: softokn3-pkcs11.c
	$(CC) -fPIC -Wall -shared -o softokn3-pkcs11.so softokn3-pkcs11.c

clean:
	rm -f ssh-agent-noasync.js.new ssh-agent-noasync.js
	rm -f softokn3-pkcs11.so

distclean: clean

.PHONY: all clean distclean
