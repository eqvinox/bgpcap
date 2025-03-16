love: \
	pcapngsplit \
	#

FRR=../frr
CC=gcc

OPT=-O2

%.o: %.c
	$(CC) -std=gnu17 -ggdb3 $(OPT) -fno-omit-frame-pointer \
		-Wall -Wextra -Wshadow -Werror -fms-extensions \
		-Wno-unused -Wno-format -Wno-address-of-packed-member \
		-I $(FRR)/lib/assert -I $(FRR)/lib -I $(FRR) \
		-c -o $@ $<

%: %.o \
		$(FRR)/lib/printf/vfprintf.o \
		$(FRR)/lib/printf/printf-pos.o \
		$(FRR)/lib/printf/glue.o \
		$(FRR)/lib/strformat.o \
		$(FRR)/lib/memory.o \
		$(FRR)/lib/typesafe.o \
		$(FRR)/lib/typerb.o \
		$(FRR)/lib/jhash.o \
		$(FRR)/lib/prefix.o \
		$(FRR)/lib/sockunion.o \
		stubs.o \
		#
	$(CC) -ggdb3 $(OPT) -o $@ $^
