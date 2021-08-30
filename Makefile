CC     = clang++
CFLAGS = -Wall -std=c++17 -g
LDLIBS = -lsodium

server:
	rm -f server.out
	$(CC) $(CFLAGS) -o server.out \
		aegis256/aegis256.c  \
		src/mud.cpp \
		src/addr.cpp \
		src/sockaddress.cpp \
		src/stat.cpp \
		src/path.cpp \
		src/paths.cpp \
		src/crypto_keys.cpp \
		src/crypto_key.cpp \
		test/server.cpp \
		$(LDLIBS)

client:
	rm -f client.out
	$(CC) $(CFLAGS) -o client.out \
		aegis256/aegis256.c \
		src/mud.cpp \
		src/addr.cpp \
		src/sockaddress.cpp \
		src/stat.cpp \
		src/path.cpp \
		src/paths.cpp \
		src/crypto_keys.cpp \
		src/crypto_key.cpp \
		test/client.cpp \
		$(LDLIBS)

clean:
	rm -f *.out 
	rm -rf *.dSYM

test:
	rm -f test.out
	$(CC) $(CFLAGS) $(LDLIBS) -L /usr/local/lib -lcpptest-lite -o test.out \
		aegis256/aegis256.c  \
		src/mud.cpp \
		src/addr.cpp \
		src/sockaddress.cpp \
		src/stat.cpp \
		src/path.cpp \
		src/paths.cpp \
		src/crypto_keys.cpp \
		src/crypto_key.cpp \
		test/test.cpp

.PHONY: test clean
