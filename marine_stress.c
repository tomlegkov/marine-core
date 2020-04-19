#include "marine.h"
#include "marine_dev.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void fill_random(char *buf, size_t len) {
  for (size_t i = 0; i + 3 < len; i += 4) {
    *(int *)(buf + i) = rand();
  }
}

void random_eth(char *buf) {
  fill_random(buf, 12); // randomize macs
  buf[12] = 0x08;
  buf[13] = 0;
}

void random_ip(char *buf) {
  buf += 14; // skip eth
  *(buf++) = 0x45;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 14;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0x40;
  *(buf++) = 0x06;
  *(buf++) = 0xac;
  *(buf++) = 0x16;
  fill_random(buf, 8); // randomize ips
}

void random_tcp(char *buf) {
  buf += 14; // skip eth
  buf += 20; // skip ip
  fill_random(buf, 4); // randomize ports
  buf += 4;
  *(buf++) = 0xde;
  *(buf++) = 0xad;
  *(buf++) = 0xbe;
  *(buf++) = 0xef;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0x50;
  *(buf++) = 0x02;
  *(buf++) = 0xff;
  *(buf++) = 0xff;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0;
  *(buf++) = 0;
}

// Incredibly non thread safe but I just don't care
static char format_mem_buf[128] = {0};
char *format_mem(size_t rss) {
  sprintf(format_mem_buf, "MEMORY: %.2lfMB", rss / 1024.0 / 1024.0);
  return format_mem_buf;
}

#define DATA_LEN 800
#define CHUNK (1U << 19U)
int main(int argc, char **argv) {
  srand(time(NULL));
  if (argv != NULL) {
    printf("argc: %d\n", argc);
  }
  char *fields[] = {"eth.src", "eth.dst", "tcp.srcport"};
  char err_msg[512] = {0};
  printf("%s\n", format_mem(get_current_rss()));
  printf("Loading marine...\n");
  init_marine();
  printf("%s\n", format_mem(get_current_rss()));
  printf("Adding filter\n");
  int filter_id = marine_add_filter("ether[0] & 1 == 0", "frame[0] & 2", fields,
                                    3, err_msg);
  if (filter_id < 0) {
    printf("Could not add filter: %s", err_msg);
    return -1;
  }
  char data[DATA_LEN] = {0};
  size_t rss = get_current_rss();
  printf("%s\n", format_mem(get_current_rss()));
  size_t prev_rss;
  for (size_t i = 1; i < (32U << 20U); ++i) {
    if ((i & (CHUNK - 1U)) == 0) {
      printf("LOOP %ld\n", i);
      prev_rss = rss;
      rss = get_current_rss();
      printf("%s (%.2lf bpp)\n", format_mem(rss), ((double)(rss - prev_rss)) / CHUNK);
    }
    fill_random(data, DATA_LEN);
    random_eth(data);
    unsigned int flags = rand();
    if ((flags & 1U) == 0) {
      random_ip(data);
    }
    if ((flags & 3U) == 0) {
      random_tcp(data);
    }
    marine_free(marine_dissect_packet(filter_id, data, DATA_LEN));
  }
  destroy_marine();
  return 0;
}
