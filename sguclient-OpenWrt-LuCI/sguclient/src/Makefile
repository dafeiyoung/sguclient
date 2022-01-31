OBJECTS=sguclient

LDFLAGS+=-lpcap -lpthread

all: $(OBJECTS)
PKG_NAME=docs
	 
sguclient: main.o md5.o sguclient.o public.o dprotocol.o
	$(CC) $(LDFLAGS) $^ -o $@
sguclient.o:sguclient.c
	$(CC) $(CFLAGS)  -c $<
main.o:main.c
	$(CC) $(CFLAGS)  -c $<
md5.o:md5.c
	$(CC) $(CFLAGS)  -c $<
public.o:public.c
	$(CC) $(CFLAGS)  -c $<
dprotocol.o:dprotocol.c
	$(CC) $(CFLAGS)  -c $<

.PHONY:clean
clean:
	@-rm *.o  sguclient
