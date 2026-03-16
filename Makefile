.PHONY: all clean fmt lint docs spec

all: clean fmt lint docs spec

fmt:
	crystal tool format src/ spec/

spec:
	crystal spec --verbose

lint: lib/ameba/bin/ameba
	lib/ameba/bin/ameba

lib/ameba/bin/ameba:
	shards install

docs:
	crystal docs

clean:
	rm -rf docs/
