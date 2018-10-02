CC = gcc
INCLUDE = ./
OBJS = main.o cpu_util.o

cpuutil:${OBJS}
	${CC} -I${INCLUDE} -o $@ ${OBJS}
