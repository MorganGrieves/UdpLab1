BUILD_DIR=build
STAT_PRINT_VERSION=0.0.1
UDP_COUNTER_VERSION=0.0.1
CC=gcc
CFLAGS= -std=gnu11 -g -Werror -pedantic -Wall
SRCS=udp_counter.c stat_print.c pac_stat.c

DBDIR = $(BUILD_DIR)/debug
DBSRC_UDP_COUNTER = udp_counter.c pac_stat.c
DBSRC_STAT_PRINT = stat_print.c pac_stat.c
DBCFLAGS = -g -DDEBUG -pg

RELDIR = $(BUILD_DIR)/release
RELSRC_UDP_COUNTER = udp_counter.c pac_stat.c
RELSRC_STAT_PRINT = stat_print.c pac_stat.c
RELCFLAGS =

.PHONY: debug, release
package:
	$(CC) $(CFLAGS) -o ./udp-counter_$(STAT_PRINT_VERSION)/usr/bin/udp-counter $(RELSRC_UDP_COUNTER) -pthread -lrt
	$(CC) $(CFLAGS) -o ./stat-print_$(UDP_COUNTER_VERSION)/usr/bin/stat-print $(RELSRC_STAT_PRINT) -lrt
	dpkg-deb --build ./udp-counter_$(STAT_PRINT_VERSION)
	dpkg-deb --build ./stat-print_$(UDP_COUNTER_VERSION)

debug:
	mkdir -p $(DBDIR)
	$(CC) $(CFLAGS) $(DBCFLAGS) -o $(DBDIR)/udp-counter $(DBSRC_UDP_COUNTER) -pthread -lrt
	$(CC) $(CFLAGS) $(DBCFLAGS) -o $(DBDIR)/stat-print $(DBSRC_STAT_PRINT) -lrt

release:
	mkdir -p $(RELDIR)/
	$(CC) $(CFLAGS) -o $(RELDIR)/udp-counter $(RELSRC_UDP_COUNTER) -pthread -lrt
	$(CC) $(CFLAGS) -o $(RELDIR)/stat-print $(RELSRC_STAT_PRINT) -lrt
clean:
	rm -rf $(DBDIR) $(RELDIR)
