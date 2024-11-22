CC      = gcc
CFLAGS  = -ansi -pedantic -Wall -Wextra -Werror -Wfatal-errors -fpic -O3
LDLIBS  = -lpthread
DEST    = cs238
SRCS    = device.c logfs.c kvraw.c main.c utils.c  # Add all source files here
OBJS    := $(SRCS:.c=.o)
DEPS    := $(OBJS:.o=.d)

all: $(DEST)

$(DEST): $(OBJS)
	@echo "[LN]" $@
	@$(CC) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	@echo "[CC]" $<
	@$(CC) $(CFLAGS) -c $<
	@$(CC) $(CFLAGS) -MM $< > $*.d

clean:
	@rm -f $(DEST) *.so *.o *.d *~

-include $(DEPS)
