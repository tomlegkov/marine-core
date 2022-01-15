#ifndef WIRESHARK_MARINE_H


#define WIRESHARK_MARINE_H

#include <glib.h>
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))

typedef struct {
    char **output;
    unsigned int len;
    int result;
} marine_result;

int init_marine(void);
void set_epan_auto_reset_count(guint32 auto_reset_count);
marine_result *marine_dissect_packet(int filter_id, unsigned char *data, int len);
int marine_add_filter(char *bpf, char *dfilter, char **fields, int* macro_indices, unsigned int fields_len, int wtap_encap, char **err_msg);
void marine_free_err_msg(char *ptr);
void marine_free(marine_result *ptr);
void marine_report_fields(void);
void destroy_marine(void);


enum marine_packet_field_value_type {
    MARINE_VT_NONE,
    MARINE_VT_INT,
    MARINE_VT_UINT,
    MARINE_VT_BOOL,
    MARINE_VT_STR,
    MARINE_VT_BYTES,
    MARINE_VT_LIST
};

typedef struct _marine_packet_field_value {
    union {
        long int_value;
        unsigned long uint_value;
        unsigned char bool_value;
        char *str_value;
        struct _marine_packet_field_value *list_value;
    };
    unsigned int len;
    enum marine_packet_field_value_type type;
} marine_packet_field_value;

typedef struct {
    char *name;
    GArray *children;
    marine_packet_field_value value;
} marine_packet_field;

typedef struct {
    unsigned char *source_packet;
    unsigned int source_packet_length;
    marine_packet_field *layer_tree;
} marine_packet;

marine_packet *marine_dissect_all_packet_fields(unsigned char *packet, int len, int wtap_encap);

void marine_packet_free(marine_packet *packet);


extern const unsigned int ETHERNET_ENCAP;
extern const unsigned int WIFI_ENCAP;
extern const int MARINE_ALREADY_INITIALIZED_ERROR_CODE;
extern const int MARINE_INIT_INTERNAL_ERROR_CODE;


extern const int BAD_BPF_ERROR_CODE;
extern const int BAD_DISPLAY_FILTER_ERROR_CODE;
extern const int INVALID_FIELD_ERROR_CODE;

#endif //WIRESHARK_MARINE_H
