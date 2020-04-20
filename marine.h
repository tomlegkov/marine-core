#ifndef WIRESHARK_MARINE_H


#define WIRESHARK_MARINE_H

#include <glib.h>
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))

// The options must be mutable so need to create them as this
// prefs_set_pref change the string, so we have to pass a mutable string
// By: char* prefs[] - it will create an hardcoded literal in the program binary and wont work (segv)
typedef char marine_pref_t[1024];

typedef struct {
    char *output;
    int result;
} marine_result;

int init_marine(void);
void set_epan_auto_reset_count(guint32 auto_reset_count);
marine_result *marine_dissect_packet(int filter_id, unsigned char *data, int len);
int marine_add_filter(char *bpf, char *dfilter, char **fields, int fields_len, char *err_msg);
int set_preferences(marine_pref_t* preferences, int num_of_prefs);
void marine_free(marine_result *ptr);
void destroy_marine(void);

#endif //WIRESHARK_MARINE_H
