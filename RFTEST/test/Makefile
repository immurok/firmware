# host 纯逻辑单测(不依赖 SDK)
CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -g -I..
SRC = ../ftm_parse.c test_ftm_parse.c

.PHONY: test clean

test: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o test_ftm_parse
	./test_ftm_parse

clean:
	rm -rf test_ftm_parse test_ftm_parse.dSYM
