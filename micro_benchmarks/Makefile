CC        = g++
CPPFLAGS  = -Wall -I../include -O3 # -g
LIB       = -lv8 -lpthread
LIBS_PATH = ..

all: accessor_bench

accessor_bench: accessor_bench.o
	$(CC) $(CFLAGS) -o accessor_bench accessor_bench.o -L$(LIBS_PATH) $(LIB)

clean:
	rm -f accessor_bench.o accessor_bench
