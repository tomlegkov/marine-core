#include <stdio.h>
#include <pcap.h>
#include "marine.h"
#include "marine_dev.h"
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>

#define BENCH_RUNS 7
#define BENCH_KEEP 3

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

int compare_doubles(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    return (da > db) - (da < db);
}

double average_fastest_runs(double times[], int n, int keep) {
    qsort(times, n, sizeof(double), compare_doubles);
    double sum = 0;
    for (int i = 0; i < keep; i++) {
        sum += times[i];
    }
    return sum / keep;
}

void print_benchmark_results(double avg_time, size_t memory_start, size_t memory_end, int packet_len) {
    double pps = packet_len / avg_time;
    double memory_usage = (memory_end - memory_start) / 1024.0 / 1024.0;
    printf("%d packets took: %f Sec (avg of fastest %d/%d runs), which is %f pps!\nmemory usage: %lf MB\n",
           packet_len, avg_time, BENCH_KEEP, BENCH_RUNS, pps, memory_usage);
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

    double times[BENCH_RUNS];
    size_t memory_start = get_current_rss();

    for (int run = 0; run < BENCH_RUNS; run++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
        for (int i = 0; i < packet_len; ++i) {
            packet p = packets[i];
            marine_result *result = marine_dissect_packet(filter_id, (char *) p.data, p.header->len);
            assert(result->result == 1);
            marine_free(result);
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
        times[run] = (end_time.tv_sec - start_time.tv_sec) + ((end_time.tv_nsec - start_time.tv_nsec) * 1e-9);
        printf("  run %d/%d: %f sec\n", run + 1, BENCH_RUNS, times[run]);
    }

    size_t memory_end = get_current_rss();
    double avg_time = average_fastest_runs(times, BENCH_RUNS, BENCH_KEEP);
    print_benchmark_results(avg_time, memory_start, memory_end, packet_len);
}


int print_title(char *str) {
    return printf("\n\033[4:1m%s\033[0m\n", str);
}

void benchmark_dissect_all_packet_fields(packet packets[], int packet_len, int encapsulation_type) {
    struct timespec start_time, end_time;
    double times[BENCH_RUNS];

    size_t memory_start = get_current_rss();

    for (int run = 0; run < BENCH_RUNS; run++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
        for (int i = 0; i < packet_len; i++) {
            packet p = packets[i];
            marine_packet *pkt = marine_dissect_all_packet_fields((char *) p.data, p.header->len, encapsulation_type);
            marine_packet_free(pkt);
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
        times[run] = (end_time.tv_sec - start_time.tv_sec) + ((end_time.tv_nsec - start_time.tv_nsec) * 1e-9);
        printf("  run %d/%d: %f sec\n", run + 1, BENCH_RUNS, times[run]);
    }

    size_t memory_end = get_current_rss();
    double avg_time = average_fastest_runs(times, BENCH_RUNS, BENCH_KEEP);
    print_benchmark_results(avg_time, memory_start, memory_end, packet_len);
}

/* ---------- Sanity checks using hardcoded packets ---------- */

static void check(int cond, const char *fmt, ...) {
    if (cond) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "\n[SANITY FAIL] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

/*
 * Minimal Ethernet/IPv4/TCP packet (54 bytes):
 *   dst=00:00:00:87:7e:0e  src=00:00:00:9f:f8:3b  type=0x0800
 *   IPv4: version=4, ihl=5 (20 bytes), total_len=40, proto=6 (TCP)
 *         src=88.44.85.145 (0x582c5591)  dst=212.110.118.170 (0xd46e76aa)
 *   TCP:  sport=4010 (0x0faa)  dport=4011 (0x0fab)  seq=0 ack=0
 *         data_offset=5 (20 bytes), flags=0x02 (SYN), window=65535
 */
static const unsigned char PKT_TCP[] = {
    /* Ethernet header (14 bytes) */
    0x00, 0x00, 0x00, 0x87, 0x7e, 0x0e, /* dst MAC */
    0x00, 0x00, 0x00, 0x9f, 0xf8, 0x3b, /* src MAC */
    0x08, 0x00,                         /* EtherType: IPv4 */
    /* IPv4 header (20 bytes) */
    0x45, 0x00,                         /* version=4, ihl=5, dscp=0 */
    0x00, 0x28,                         /* total length = 40 */
    0x00, 0x01, 0x00, 0x00,             /* id=1, flags=0, frag_offset=0 */
    0x40, 0x06,                         /* ttl=64, proto=6 (TCP) */
    0x00, 0x00,                         /* checksum (0 = let wireshark recalc) */
    0x58, 0x2c, 0x55, 0x91,             /* src IP: 88.44.85.145 */
    0xd4, 0x6e, 0x76, 0xaa,             /* dst IP: 212.110.118.170 */
    /* TCP header (20 bytes) */
    0x0f, 0xaa,                         /* src port: 4010 */
    0x0f, 0xab,                         /* dst port: 4011 */
    0x00, 0x00, 0x00, 0x00,             /* sequence number */
    0x00, 0x00, 0x00, 0x00,             /* ack number */
    0x50, 0x02,                         /* data offset=5, flags=SYN */
    0xff, 0xff,                         /* window size */
    0x00, 0x00,                         /* checksum */
    0x00, 0x00                          /* urgent pointer */
};

/*
 * Minimal Ethernet/IPv4/UDP packet (42 bytes):
 *   Same Ethernet + IPv4 headers as above, but proto=17 (UDP)
 *   UDP: sport=4010 dport=4011 len=8
 */
static const unsigned char PKT_UDP[] = {
    /* Ethernet header (14 bytes) */
    0x00, 0x00, 0x00, 0x87, 0x7e, 0x0e,
    0x00, 0x00, 0x00, 0x9f, 0xf8, 0x3b,
    0x08, 0x00,
    /* IPv4 header (20 bytes) */
    0x45, 0x00,
    0x00, 0x1c,                         /* total length = 28 */
    0x00, 0x02, 0x00, 0x00,
    0x40, 0x11,                         /* ttl=64, proto=17 (UDP) */
    0x00, 0x00,
    0x58, 0x2c, 0x55, 0x91,
    0xd4, 0x6e, 0x76, 0xaa,
    /* UDP header (8 bytes) */
    0x0f, 0xaa,                         /* src port: 4010 */
    0x0f, 0xab,                         /* dst port: 4011 */
    0x00, 0x08,                         /* length: 8 (header only) */
    0x00, 0x00                          /* checksum */
};

/*
 * Validate field extraction correctness using hardcoded packets.
 * Runs before benchmarks; exits on failure to prevent misleading results.
 */
void validate_extraction(void) {
    char *err_msg;
    printf("Running sanity checks...\n");

    /* --- 1. BPF-only: TCP packet must pass, no output --- */
    {
        int fid = marine_add_filter("tcp port 4010", NULL, NULL, NULL, 0, ETHERNET_ENCAP, &err_msg);
        check(fid >= 0, "BPF-only filter creation failed: %s", err_msg);
        marine_result *r = marine_dissect_packet(fid, (unsigned char *)PKT_TCP, sizeof(PKT_TCP));
        check(r->result == 1, "BPF-only: TCP packet did not pass");
        check(r->output == NULL, "BPF-only: expected NULL output");
        marine_free(r);
    }

    /* --- 2. Display-filter-only: must pass, no output --- */
    {
        int fid = marine_add_filter(NULL, "tcp.port == 4010", NULL, NULL, 0, ETHERNET_ENCAP, &err_msg);
        check(fid >= 0, "Display-filter-only creation failed: %s", err_msg);
        marine_result *r = marine_dissect_packet(fid, (unsigned char *)PKT_TCP, sizeof(PKT_TCP));
        check(r->result == 1, "Display-filter-only: packet did not pass");
        check(r->output == NULL, "Display-filter-only: expected NULL output");
        marine_free(r);
    }

    /* --- 3. Eight-field extraction on TCP packet --- */
    {
        char *fields[] = {
            "ip.proto", "tcp.srcport", "udp.srcport", "eth.src",
            "ip.host", "ip.hdr_len", "ip.version", "frame.encap_type"
        };
        int fid = marine_add_filter(NULL, NULL, fields, NULL, ARRAY_SIZE(fields), ETHERNET_ENCAP, &err_msg);
        check(fid >= 0, "Field extraction filter creation failed: %s", err_msg);

        marine_result *r = marine_dissect_packet(fid, (unsigned char *)PKT_TCP, sizeof(PKT_TCP));
        check(r->result == 1, "Field extraction: TCP packet did not pass");
        check(r->len == 8, "Field extraction: expected 8 slots, got %u", r->len);

        check(r->output[0] != NULL && strcmp(r->output[0], "6") == 0,
              "ip.proto expected '6', got '%s'", r->output[0] ? r->output[0] : "(null)");
        check(r->output[1] != NULL && strcmp(r->output[1], "4010") == 0,
              "tcp.srcport expected '4010', got '%s'", r->output[1] ? r->output[1] : "(null)");
        check(r->output[2] == NULL,
              "udp.srcport should be NULL for TCP, got '%s'", r->output[2] ? r->output[2] : "(null)");
        check(r->output[3] != NULL && strcmp(r->output[3], "00:00:00:9f:f8:3b") == 0,
              "eth.src expected '00:00:00:9f:f8:3b', got '%s'", r->output[3] ? r->output[3] : "(null)");
        check(r->output[4] != NULL,
              "ip.host is NULL");
        check(r->output[5] != NULL && strcmp(r->output[5], "20") == 0,
              "ip.hdr_len expected '20', got '%s'", r->output[5] ? r->output[5] : "(null)");
        check(r->output[6] != NULL && strcmp(r->output[6], "4") == 0,
              "ip.version expected '4', got '%s'", r->output[6] ? r->output[6] : "(null)");
        check(r->output[7] != NULL && strcmp(r->output[7], "1") == 0,
              "frame.encap_type expected '1', got '%s'", r->output[7] ? r->output[7] : "(null)");

        marine_free(r);
    }

    /* --- 4. Stale value: TCP then UDP — tcp.srcport must be NULL for UDP --- */
    {
        char *fields[] = { "ip.proto", "tcp.srcport", "udp.srcport" };
        int fid = marine_add_filter(NULL, NULL, fields, NULL, ARRAY_SIZE(fields), ETHERNET_ENCAP, &err_msg);
        check(fid >= 0, "Stale-value filter creation failed: %s", err_msg);

        marine_result *r1 = marine_dissect_packet(fid, (unsigned char *)PKT_TCP, sizeof(PKT_TCP));
        check(r1->output[0] != NULL && strcmp(r1->output[0], "6") == 0, "Stale: TCP ip.proto != '6'");
        check(r1->output[1] != NULL, "Stale: tcp.srcport NULL for TCP packet");
        marine_free(r1);

        marine_result *r2 = marine_dissect_packet(fid, (unsigned char *)PKT_UDP, sizeof(PKT_UDP));
        check(r2->output[0] != NULL && strcmp(r2->output[0], "17") == 0, "Stale: UDP ip.proto != '17'");
        check(r2->output[1] == NULL,
              "Stale: tcp.srcport not NULL for UDP packet: '%s'", r2->output[1] ? r2->output[1] : "");
        check(r2->output[2] != NULL && strcmp(r2->output[2], "4010") == 0,
              "Stale: udp.srcport expected '4010', got '%s'", r2->output[2] ? r2->output[2] : "(null)");
        marine_free(r2);
    }

    /* --- 5. epan_auto_reset boundary: fields correct across reset --- */
    {
        char *fields[] = { "ip.version", "frame.encap_type" };
        int fid = marine_add_filter(NULL, NULL, fields, NULL, ARRAY_SIZE(fields), ETHERNET_ENCAP, &err_msg);
        check(fid >= 0, "Reset-boundary filter creation failed: %s", err_msg);

        set_epan_auto_reset_count(3);
        for (int i = 0; i < 5; i++) {
            /* Alternate TCP/UDP to exercise both packets across the reset */
            const unsigned char *pkt = (i % 2 == 0) ? PKT_TCP : PKT_UDP;
            int pkt_len = (i % 2 == 0) ? (int)sizeof(PKT_TCP) : (int)sizeof(PKT_UDP);
            marine_result *r = marine_dissect_packet(fid, (unsigned char *)pkt, pkt_len);
            check(r->result == 1, "Reset-boundary: packet %d did not pass", i);
            check(r->output[0] != NULL && strcmp(r->output[0], "4") == 0,
                  "Reset-boundary: ip.version at pkt %d expected '4', got '%s'", i, r->output[0] ? r->output[0] : "(null)");
            check(r->output[1] != NULL && strcmp(r->output[1], "1") == 0,
                  "Reset-boundary: frame.encap_type at pkt %d expected '1', got '%s'", i, r->output[1] ? r->output[1] : "(null)");
            marine_free(r);
        }
        set_epan_auto_reset_count(100000);
    }

    printf("All sanity checks passed.\n\n");
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
    validate_extraction();
    run_dissect_packet_benchmarks(packets, packet_count, encap_type);
    run_dissect_all_packet_fields_benchmarks(packets, packet_count, encap_type);
    destroy_marine();
    free(packets);
    return 0;
}

