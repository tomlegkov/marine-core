#include "marine.h"
#include "marine_dev.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define PACKET_LEN 800U
#define ETH_HEADER_LEN 14U
#define IP_LEN (PACKET_LEN - ETH_HEADER_LEN)

void fill_random(char *buf, size_t len) {
    for (size_t i = 0; i < len / sizeof(int); ++i) {
        *(((int *)buf) + i) = rand();
    }
}

void random_ip(char *buf) {
    buf[12] = 0x08; // set ethertype to ipv4
    buf[13] = 0;
    buf += 14;       // skip eth
    *(buf++) = 0x45; // version and len
    *(buf++) = 0;
    *(buf++) = (IP_LEN >> 8U) & 0xFFU;
    *(buf++) = IP_LEN & 0xFFU;
    fill_random(buf, 4);
    buf += 2;             // ip id, leave random
    *(buf++) = 0;         // flags and fragment
    *(buf++) = 0;         // fragment
    fill_random(buf, 12); // randomize TTL, protocol, checksum and ips
}

void random_tcp(char *buf) {
    buf += 14;           // skip eth
    buf[9] = 6;          // set ip type to tcp
    buf += 20;           // skip ip
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

int report_mem(size_t rss) {
    return printf("MEMORY: %.2lfMB\n", rss / 1024.0 / 1024.0);
}

size_t report_current_mem(void) {
    size_t rss = get_current_rss();
    report_mem(rss);
    return rss;
}

#define CHUNK (1U << 17U)
#define TOTAL_PACKETS (CHUNK << 3U)

int main(void) {
    srand(0);
    char *fields[] = {"eth.src", "ip.dst", "tcp.srcport"};
    char *err_msg;
    report_current_mem();
    printf("Loading marine...\n");
    set_epan_auto_reset_count(CHUNK);
    init_marine();
    report_current_mem();
    printf("Adding filter\n");
    int filter_id = marine_add_filter("ether[0] & 1 == 0", "frame[0] & 2",
                                      fields, 3, &err_msg);
    if (filter_id < 0) {
        fprintf(stderr, "Could not add filter: %s\n", err_msg);
        marine_free_err_msg(err_msg);
        return -1;
    }
    char data[PACKET_LEN] = {0};
    size_t prev_rss;
    size_t rss = report_current_mem();
    double bytes_per_packet;
    double total_bytes_per_packet = 0;
    size_t chunks = 0;
    for (size_t i = 1; i <= TOTAL_PACKETS; ++i) {
        fill_random(data, PACKET_LEN);
        unsigned int flags = rand();
        if ((flags & 1U) == 0) {
            random_ip(data);
            if ((flags & 2U) == 0) {
                random_tcp(data);
            }
        }
        marine_free(marine_dissect_packet(filter_id, data, PACKET_LEN));
        if (i % CHUNK == 0) {
            prev_rss = rss;
            rss = get_current_rss();
            // cast to long long to handle negative numbers properly
            bytes_per_packet = ((double) (long long)(rss - prev_rss)) / CHUNK;
            total_bytes_per_packet += bytes_per_packet;
            ++chunks;
            printf("CHUNK #%ld: BYTES-PER-PACKET: %.2lf, ", chunks, bytes_per_packet);
            report_mem(rss);
        }
    }
    printf("\nTOTAL\n----------\n");
    printf("bytes-per-packet:: %.2lf\n", total_bytes_per_packet / chunks);
    destroy_marine();
    return 0;
}
