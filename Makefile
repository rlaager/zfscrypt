PREFIX ?= /usr

SRCDIR ?= ./src
INCDIR ?= ./include
DESTDIR ?= ./build

# libspl is incompatible with -std=c18
CFLAGS := -std=gnu18 -g -Og -Wall -Wextra -Wpedantic -fPIC -fno-stack-protector -flto -I$(INCDIR) -MMD -MP
ZFSINC := -isystem/usr/include/libzfs -isystem/usr/include/libspl

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(DESTDIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

.PHONY: all clean build install test

all: clean build

clean:
	rm -rf $(DESTDIR)
	mkdir -p $(DESTDIR)

build: $(DESTDIR)/pam_zfscrypt.so

$(DESTDIR)/pam_zfscrypt.so: $(OBJS)
	$(CC) $(CFLAGS) -shared -Xlinker -x -o $@ $^ -lzfs -lnvpair

$(DESTDIR)/pam_zfscrypt.o: $(SRCDIR)/pam_zfscrypt.c
	$(CC) $(CFLAGS) $(ZFSINC) -c -o $@ $<

$(DESTDIR)/zfscrypt_context.o: $(SRCDIR)/zfscrypt_context.c
	$(CC) $(CFLAGS) $(ZFSINC) -c -o $@ $<

$(DESTDIR)/zfscrypt_dataset.o: $(SRCDIR)/zfscrypt_dataset.c
	$(CC) $(CFLAGS) $(ZFSINC) -c -o $@ $<

$(DESTDIR)/zfscrypt_err.o: $(SRCDIR)/zfscrypt_err.c
	$(CC) $(CFLAGS) $(ZFSINC) -c -o $@ $<

$(DESTDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(DESTDIR)/pam_zfscrypt.so
	install -m 0755 -s $< $(PREFIX)/lib/security/pam_zfscrypt.so

test:
	$(CC) $(CFLAGS) -g -Og -o $(DESTDIR)/test ./test/test.c -lpam
	$(DESTDIR)/test

-include $(DEPS)
