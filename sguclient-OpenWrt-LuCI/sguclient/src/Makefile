TARGET = sguclient	
OBJECTS=sguclient

LIBS = -lpcap -lpthread

C_SOURCES       = $(wildcard *.c)
C_OBJS = $(patsubst %.c, %.o, $(C_SOURCES))

all: $(TARGET)

%.o:%.c
	$(CC) -c $< $(CCFLAGS)
	
$(TARGET): $(C_OBJS)
	$(CC) -o $(TARGET) $^ $(LIBS)
	
.PHONY:clean
clean:
	@-rm *.o  $(TARGET)
