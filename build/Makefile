# Example makefile for CPE464 program 1
#
# 

CC = g++
CFLAGS = -g -Wall 
#CFLAGS = -g

all:  trace

trace: ../src/trace.cpp ../src/checksum.c
	$(CC) $(CFLAGS) -o trace ../src/trace.cpp ../src/checksum.c  -lpcap 

clean:
	rm -f trace
