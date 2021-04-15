CC     = c++
CFLAGS = -Wall -O2
LDLIBS = -lsodium

server:
	$(CC) $(CFLAGS) -o build/server \
		aegis256/aegis256.c  \
		src/mud.cpp \
		test/server.cpp \
		$(LDLIBS)

client:
	rm -f build/client
	$(CC) $(CFLAGS) -o build/client \
		aegis256/aegis256.c \
		src/mud.cpp \
		test/client.cpp \
		$(LDLIBS)

clean:
	rm -f build/client

.PHONY: test clean
