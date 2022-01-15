#include <stdio.h>
#include <pcap.h>
#include "marine.h"
#include "marine_dev.h"
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

typedef struct {
    char *title;
    char *bpf;
    char *dfilter;
    char **fields;
    int *macro_indices;
    unsigned int num_of_fields;
} benchmark_case;

typedef struct {
    struct pcap_pkthdr *header;
    const u_char *data;
} packet;

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

void print_benchmark_results(struct timespec start_time, struct timespec end_time, size_t memory_start, size_t memory_end, int packet_len) {
    double total_time = (end_time.tv_sec - start_time.tv_sec) + ((end_time.tv_nsec - start_time.tv_nsec) * 1e-9);
    double pps = packet_len / total_time;
    double memory_usage = (memory_end - memory_start) / 1024.0 / 1024.0;
    printf("%d packets took: %f Sec, which is %f pps!\nmemory usage: %lf MB\n", packet_len, total_time, pps,
           memory_usage);
}

void benchmark(packet packets[], int packet_len, char *bpf, char *display_filter, char *fields[], int* macro_indices, unsigned int fields_len, int encapsulation_type) {
    char *err_msg;
    int filter_id = marine_add_filter(bpf, display_filter, fields, macro_indices, fields_len, encapsulation_type, &err_msg);
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
        marine_result *result = marine_dissect_packet(filter_id, (char *) p.data, p.header->len);
        assert(result->result == 1);
        marine_free(result);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    size_t memory_end = get_current_rss();

    print_benchmark_results(start_time, end_time, memory_start, memory_end, packet_len);
}


int print_title(char *str) {
    return printf("\n\033[4:1m%s\033[0m\n", str);
}

void benchmark_dissect_all_packet_fields(packet packets[], int packet_len, int encapsulation_type) {
    struct timespec start_time, end_time;


    size_t memory_start = get_current_rss();
    clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
    for (int i = 0; i < packet_len; i++) {
        packet p = packets[i];
        marine_packet *pkt = marine_dissect_all_packet_fields((char *) p.data, p.header->len, encapsulation_type);
        marine_packet_free(pkt);
    }
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    size_t memory_end = get_current_rss();

    print_benchmark_results(start_time, end_time, memory_start, memory_end, packet_len);
}

void run_dissect_packet_benchmarks(packet packets[], int packet_count, int encap_type) {

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
            {"Benchmark with BPF",                                            bpf,  NULL,    NULL,         NULL,           0},
            {"Benchmark with Display filter",                                 NULL, dfilter, NULL,         NULL,           0},
            {"Benchmark with BPF and Display filter",                         bpf,  dfilter, NULL,         NULL,           0},
            {"Benchmark with three extracted fields",                         NULL, NULL,    three_fields, NULL, ARRAY_SIZE(three_fields)},
            {"Benchmark with eight extracted fields",                         NULL, NULL,    eight_fields, NULL, ARRAY_SIZE(eight_fields)},
            {"Benchmark with BPF, Display filter and three extracted fields", bpf,  dfilter, three_fields, NULL, ARRAY_SIZE(three_fields)},
            {"Benchmark with BPF, Display filter and eight extracted fields", bpf,  dfilter, eight_fields, NULL, ARRAY_SIZE(eight_fields)},
    };

    int num_of_cases = ARRAY_SIZE(cases);
    int packet_per_case = packet_count / num_of_cases;

    // This will make sure that each test will be cleared and avoid random in memory usages
    set_epan_auto_reset_count(packet_per_case);
    size_t memory_start = get_current_rss();

    for (int case_index = 0; case_index < num_of_cases; ++case_index) {
        benchmark_case current = cases[case_index];
        packet *start_packet = packets + (packet_per_case * case_index);

        print_title(current.title);
        benchmark(start_packet, packet_per_case, current.bpf, current.dfilter, current.fields, current.macro_indices,
                current.num_of_fields, encap_type);
    }

    size_t memory_end = get_current_rss();
    printf("\nTotal memory usage: %lf MB\n", (((float) memory_end - memory_start) / 1024 / 1024));
}

void run_dissect_all_packet_fields_benchmarks(packet packets[], int packets_count, int encap_type) {
    print_title("Benchmark dissect_all_packet_fields");
    set_epan_auto_reset_count(packets_count);
    benchmark_dissect_all_packet_fields(packets, packets_count, encap_type);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./marine_benchmark <path to cap generated by cap_maker.py> "
               "<encapsulation type value (defaults to ethernet)>\n");
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

    int encap_type = -1;
    if (argc > 2) {
        sscanf(argv[2], "%d", &encap_type);
    } else {
        encap_type = ETHERNET_ENCAP;
    }
    if (encap_type < 0) {
        fprintf(stderr, "\nCouldn't parse encapsulation type\n");
        return -1;
    }
    init_marine();
    run_dissect_packet_benchmarks(packets, packet_count, encap_type);
    run_dissect_all_packet_fields_benchmarks(packets, packet_count, encap_type);
    destroy_marine();
    free(packets);
    return 0;
}

