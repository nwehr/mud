CC     = c++
CFLAGS = -Wall -O2 -std=c++17
LDLIBS = -lsodium

server:
	rm -f build/server
	$(CC) $(CFLAGS) -o build/server \
		aegis256/aegis256.c  \
		src/mud.cpp \
		src/addr.cpp \
		src/sockaddress.cpp \
		src/stat.cpp \
		src/path.cpp \
		src/paths.cpp \
		test/server.cpp \
		$(LDLIBS)

client:
	rm -f build/client
	$(CC) $(CFLAGS) -o build/client \
		aegis256/aegis256.c \
		src/mud.cpp \
		src/addr.cpp \
		src/sockaddress.cpp \
		src/stat.cpp \
		src/path.cpp \
		src/paths.cpp \
		test/client.cpp \
		$(LDLIBS)

clean:
	rm -f build/*

.PHONY: test clean
