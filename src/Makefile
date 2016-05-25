CC = gcc
CFLAGS = -Wall -Werror -O3 -mcmodel=medium -g -I../../include

LIBS = -L../../lib -lpthread -lpcap -lyaml -lspandsp -ltiff -lm -lsndfile

OBJS += pkt_fifo.o
OBJS += conf.o
OBJS += applog.o
OBJS += connect_ma.o
OBJS += delievery.o
OBJS += util-strlcatu.o
OBJS += util-strlcpyu.o
OBJS += linkqueue.o
OBJS += pack_register_data.o
OBJS += register_sguard.o
OBJS += util-daemon.o
OBJS += voice_delivery.o

TARGET = vdu

.PHONY: all clean

all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

$(OBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJS) $(TARGET)
