TARGET = sguclient
BIN_DIR = /usr/bin/
INCLUDES = 
LIBS = -lpcap -lpthread

C_SOURCES       = $(wildcard *.c)
C_OBJS = $(patsubst %.c, %.o, $(C_SOURCES))

# ------------  generate the names of the object files  ------------------------
OBJECTS         = $(addsuffix .o,$(BASENAMES))

# ------------  generate the names of the hidden prerequisite files  -----------
PREREQUISITES   = $(addprefix .,$(addsuffix .d,$(BASENAMES)))

# ------------  make the executable (the default goal)  ------------------------
%.o:%.c
	$(CC) -c $<$ $(CCFLAGS)

$(TARGET): $(CPP_OBJS) $(C_OBJS)
	$(CXX)$(LINKFLAGS) -o $(TARGET) $^ $(LIBS)

all:$(TARGET)

clean:
	rm -f $(CPP_OBJS) $(C_OBJS)
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) $(BIN_DIR)

uninstall:
	rm -f $(BIN_DIR)/$(TARGET)

rebuild: clean all

# ==============================================================================
# vim: set tabstop=2: set shiftwidth=2:
