CC     = c++
CFLAGS = -Wall -O2
LDLIBS = -lsodium

server:
	$(CC) $(CFLAGS) -o server server.cpp mud.cpp aegis256.c  $(LDLIBS)

client:
	$(CC) $(CFLAGS) -o client client.cpp mud.cpp aegis256/aegis256.c $(LDLIBS)

clean:
	rm -f test

.PHONY: test clean
