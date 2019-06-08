all: ssh-agent-noasync.js

ssh-agent-noasync.js: ../chrome/ssh-agent.js
	cc -Dawait='' -Dasync='' -nostdinc -C -E -x c ../chrome/ssh-agent.js -o - | grep -v '^# ' > ssh-agent-noasync.js.new
	mv ssh-agent-noasync.js.new ssh-agent-noasync.js

clean:
	rm -f ssh-agent-noasync.js.new ssh-agent-noasync.js

distclean: clean

.PHONY: all clean distclean
