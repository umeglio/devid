CC := gcc
CFLAGS := -O2 -Wall -Wextra -Werror -std=c89 -pedantic
LDFLAGS := -liphlpapi -lws2_32 -lwinhttp
TARGET := dev-id.exe
SRC := src/main.c src/config.c src/ipv4.c src/passive.c src/report.c src/util.c
OBJ := $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	del /Q src\*.o *.exe report.csv scan.log 2>nul || exit 0
