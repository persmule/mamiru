all: mamiru

mamiru: shebang codepack.zip
	cat $< $(word 2,$^) > $@
	chmod +x $@

codepack.zip: *.py pgpdump
	zip `basename -s .zip $@` *.py -r pgpdump -x '*.pyc' -x '__pycache__'

clean:
	-rm mamiru codepack.zip
