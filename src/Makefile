CC=gcc
CXX=g++
MAKE=make

CFLAGS=-rdynamic -g -Wall
CXXFLAGS=-rdynamic -g -Wall

LDFLAGS=-rdynamic -levent -lpthread -lrt -lstdc++

RM=-rm -rf

SRCS+=$(wildcard *.c)
OBJS=$(SRCS:%.c=%.o)
DEPENDS=$(SRCS:%.c=%.d)


all:local

local:$(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJS):%.o:%.c
	$(CC) -c $< -o $@ $(CFLAGS)

-include $(DEPENDS)
$(DEPENDS):%.d:%.c
	set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[:]*,\1.o $@:,g' < $@.$$$$ > $@; \
	rm $@.$$$$

clean:
	$(RM) $(OBJS) $(DEPENDS) local

fake:
	@echo $(OBJS)
