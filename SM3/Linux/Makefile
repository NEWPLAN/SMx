Target:= sm3.exe
CC=gcc
CFALAGS= -Wall -Wextra
objs=sm3.o sm3test.o

cins=sm3.c sm3test.c

head=sm3.h

all:$(Target)
	@echo "make done!"

$(Target):$(objs)
	$(CC) $^ -o $@

%.o:%.c $(head)
	$(CC) -c $< -o $@


clean:
	rm -f $(Target) $(objs)
