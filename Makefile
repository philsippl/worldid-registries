.PHONY: test clean

test:
	forge test -vv

clean:
	forge clean

fmt: 
	forge fmt

all: test fmt