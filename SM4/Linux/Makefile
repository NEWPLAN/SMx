Target:= sm4.exe
CC=gcc
CFALAGS= -Wall -Wextra
objs=sm4.o sm4test.o

cins=sm4.c sm4test.c

head=sm4.h

all:$(Target)
	@echo "make done!"

$(Target):$(objs)
	$(CC) $^ -o $@

%.o: %.c $(head)
	$(CC) -c ${CFALAGS} $< -o $@


clean:
	rm -f $(Target) $(objs)
