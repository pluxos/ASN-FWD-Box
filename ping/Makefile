CC=gcc
CFLAGS=

%.o: %.c
		@$(CC) -c -o $@ $< 

ping: ping.o
		@$(CC) -o ping ping.o $(CFLAGS)

all: ping

clean:
		@rm -f ping *.o core *~

