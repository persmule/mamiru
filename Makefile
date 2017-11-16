all: mamiru

mamiru: shebang codepack.zip
	cat $< $(word 2,$^) > $@
	chmod +x $@

codepack.zip: *.py pgpdump
	zip `basename -s .zip $@` *.py
	zip `basename -s .zip $@` -r pgpdump

clearcache: pgpdump/*.pyc pgpdump/__pycache__
	-rm -r $^
clean:
	-rm mamiru codepack.zip
