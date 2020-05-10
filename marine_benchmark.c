#include <stdio.h>
#include <pcap.h>
#include "marine.h"
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <zconf.h>

#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))

typedef struct {
    char *title;
    char *bpf;
    char *dfilter;
    char **fields;
    size_t fields_len;
} benchmark_case;

typedef struct {
    struct pcap_pkthdr *header;
    const u_char *data;
} packet;


/*
* Author:  David Robert Nadeau
* Site:    http://NadeauSoftware.com/
* License: Creative Commons Attribution 3.0 Unported License
*          http://creativecommons.org/licenses/by/3.0/deed.en_US
*/
size_t get_current_rss(void) {
    long rss = 0L;
    FILE *fp = NULL;
    if ((fp = fopen("/proc/self/statm", "r")) == NULL) {
        return (size_t) 0L;
    }
    if (fscanf(fp, "%*s%ld", &rss) != 1) {
        fclose(fp);
        return (size_t) 0L;
    }
    fclose(fp);
    return (size_t) rss * (size_t) sysconf(_SC_PAGESIZE);
}

int load_cap(char *file, packet **packets, char errbuff[PCAP_ERRBUF_SIZE]) {
    printf("Start loading packets from cap\n");

    pcap_t *pcap = pcap_open_offline(file, errbuff);
    if (pcap == NULL) {
        return -1;
    }

    int allocated_packets = 16384;
    int p_count = 0;
    struct pcap_pkthdr *header;
    const u_char *data;

    packet *inner_packets = (packet *) malloc(sizeof(packet) * allocated_packets);
    while (pcap_next_ex(pcap, &header, &data) >= 0) {

        if (p_count >= allocated_packets) {
            allocated_packets *= 2;
            inner_packets = (packet *) realloc(inner_packets, allocated_packets * sizeof(packet));
        }

        packet p = {header, data};
        inner_packets[p_count] = p;
        p_count++;
    }
    inner_packets = (packet *) realloc(inner_packets, p_count * sizeof(packet));
    *packets = inner_packets;
    printf("Cap has been loaded, %d packets were loaded\n", p_count);
    return p_count;
}

void benchmark(packet packets[], int packet_len, char *bpf, char *display_filter, char *fields[], int fields_len) {
    char *err_msg;
    int filter_id = marine_add_filter(bpf, display_filter, fields, fields_len, &err_msg);
    struct timespec start_time, end_time;


    if (filter_id < 0) {
        fprintf(stderr, "Error creating filter id: %s\n", err_msg);
        marine_free_err_msg(err_msg);
        return;
    }

    size_t memory_start = get_current_rss();
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    for (int i = 0; i < packet_len; ++i) {
        packet p = packets[i];
        marine_result *result = marine_dissect_packet(filter_id, (char *) p.data, p.header->len, ethernet_encap);
        assert(result->result == 1);
        marine_free(result);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    size_t memory_end = get_current_rss();

    double total_time = (end_time.tv_sec - start_time.tv_sec) + ((end_time.tv_nsec - start_time.tv_nsec) * 1e-9);
    double pps = packet_len / total_time;
    double memory_usage = (memory_end - memory_start) / 1024.0 / 1024.0;
    printf("%d packets took: %f Sec, which is %f pps!\nmemory usage: %lf MB\n", packet_len, total_time, pps,
           memory_usage);
}

int print_title(char *str) {
    return printf("\n\033[4:1m%s\033[0m\n", str);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./marine_benchmark <path to cap generated by cap_maker.py>\n");
        return -1;
    }

    char *cap_file = argv[1];
    packet *packets;
    char errbuff[PCAP_ERRBUF_SIZE];
    int packet_count = load_cap(cap_file, &packets, errbuff);
    if (packet_count < 0) {
        fprintf(stderr, "\nCouldn't load the cap %s\n", errbuff);
        return -1;
    }

    char *bpf = "tcp portrange 4000-4019 or udp portrange 4000-4019";
    char *dfilter = "((4019 >= tcp.srcport >= 4000)"
                    " or "
                    "(4019 >= tcp.dstport >= 4000))"
                    " or "
                    "((4019 >= udp.srcport >= 4000)"
                    " or "
                    "(4019 >= udp.dstport >= 4000))";
    char *three_fields[] = {
            "ip.proto",
            "tcp.srcport",
            "udp.srcport"
    };
    char *eight_fields[] = {
            "ip.proto",
            "tcp.srcport",
            "udp.srcport",
            "eth.src",
            "ip.host",
            "ip.hdr_len",
            "ip.version",
            "frame.encap_type"
    };

    benchmark_case cases[] = {
            {"Benchmark with BPF",                                            bpf, NULL,    NULL, 0},
            {"Benchmark with Display filter",         NULL,                        dfilter, NULL, 0},
            {"Benchmark with BPF and Display filter",                         bpf, dfilter, NULL, 0},
            {"Benchmark with three extracted fields", NULL,                        NULL,    three_fields, 3},
            {"Benchmark with eight extracted fields", NULL,                        NULL,    eight_fields, 8},
            {"Benchmark with BPF, Display filter and three extracted fields", bpf, dfilter, three_fields, 3},
            {"Benchmark with BPF, Display filter and eight extracted fields", bpf, dfilter, eight_fields, 8},
    };

    int num_of_cases = ARRAY_SIZE(cases);
    int packet_per_case = packet_count / num_of_cases;

    init_marine();
    // This will make sure that each test will be cleared and avoid random in memory usages
    set_epan_auto_reset_count(packet_per_case);
    size_t memory_start = get_current_rss();

    for (int case_index = 0; case_index < num_of_cases; ++case_index) {
        benchmark_case current = cases[case_index];
        packet *start_packet = packets + (packet_per_case * case_index);

        print_title(current.title);
        benchmark(start_packet, packet_per_case, current.bpf, current.dfilter, current.fields, current.fields_len);
    }

    size_t memory_end = get_current_rss();
    printf("\nTotal memory usage: %lf MB\n", (((float) memory_end - memory_start) / 1024 / 1024));
    destroy_marine();
    free(packets);
    return 0;
}
