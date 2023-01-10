CFLAGS=-Wall -Wpedantic -fsanitize=address
LDFLAGS=-lm -fsanitize=address

all: tcpclient

tcpclient: netip.o utils.o cjson/cJSON.c md5.c
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	-rm tcpclient *.o
