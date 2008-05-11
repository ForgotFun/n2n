
N2N_VERSION="1.2"


########

CC=gcc
CFLAGS+=-g -Wall -Wshadow -Wpointer-arith -Wmissing-declarations -Wnested-externs #-static

INSTALL=install
MKDIR=mkdir -p

INSTALL_PROG=$(INSTALL) -m755
INSTALL_DOC=$(INSTALL) -m644

PREFIX?=/usr
BINDIR=$(PREFIX)/bin
SBINDIR=$(PREFIX)/sbin
MANDIR?=$(PREFIX)/share/man
MAN1DIR=$(MANDIR)/man1
MAN8DIR=$(MANDIR)/man8

N2N_LIB=n2n.a
N2N_OBJS=n2n.o minilzo.o twofish.o tuntap_linux.o tuntap_osx.o version.o
LIBS=-lpthread

APPS=edge supernode

all: $(APPS)

edge: edge.c $(N2N_LIB) n2n.h Makefile
	$(CC) $(CFLAGS) edge.c $(N2N_LIB) $(LIBS) -o edge

supernode: supernode.c $(N2N_LIB) n2n.h Makefile
	$(CC) $(CFLAGS) supernode.c $(N2N_LIB) $(LIBS) -o supernode

.c.o: n2n.h Makefile
	$(CC) $(CFLAGS) -c $<

%.gz : %
	gzip -c $< > $@

$(N2N_LIB): $(N2N_OBJS)
	ar rcs $(N2N_LIB) $(N2N_OBJS)
#	$(RANLIB) $@

version.c:
	echo $(N2N_VERSION) | sed -e 's/.*/char * version   = "&";/' > version.c
	uname -p | sed -e 's/.*/char * osName    = "&";/' >> version.c
	date +"%D %r" | sed -e 's/.*/char * buildDate = "&";/' >> version.c

clean:
	rm -rf $(N2N_OBJS) $(N2N_LIB) $(APPS) *.dSYM *~ version.c

install: edge supernode edge.8.gz supernode.1.gz
	$(MKDIR) $(BINDIR) $(SBINDIR) $(MAN1DIR) $(MAN8DIR)
	$(INSTALL_PROG) supernode $(BINDIR)/
	$(INSTALL_PROG) edge $(SBINDIR)/
	$(INSTALL_DOC) edge.8.gz $(MAN8DIR)/
	$(INSTALL_DOC) supernode.1.gz $(MAN1DIR)/
