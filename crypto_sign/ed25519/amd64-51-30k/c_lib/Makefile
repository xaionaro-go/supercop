NAME=amd64_51_30k

CC= gcc
CFLAGS= -Wall -Wextra -O3 -fwrapv -fPIC -I/usr/include/sodium
LDFLAGS= $(shell pkg-config --libs libsodium)
ifeq ($(CC),gcc)
LDFLAGS+= -flto=8 -Wl,--gc-sections
CFLAGS+= -fdata-sections -ffunction-sections
endif

TARGETS=$(NAME).a

LIB_SRCS=$(wildcard ../../../../internal/c_impl/crypto_sign/ed25519/amd64-51-30k/*.[sc])
LIB_OBJS=$(patsubst %.c,%.o,$(patsubst %.s,%.o,$(LIB_SRCS)))

all: $(TARGETS)

clean:
	-rm -f $(TARGETS) $(LIB_OBJS)

%.so: $(LIB_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH) -fPIC -shared -o ed25519.so $(LIB_OBJS)

%.a: $(LIB_OBJS)
	ar rcs lib$@ $(LIB_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $^

%.o: %.s
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $^

