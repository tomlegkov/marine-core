#ifndef WIRESHARK_MARINE_PREFS_H
#define WIRESHARK_MARINE_PREFS_H

int marine_prefs_list_module_prefs(char *module_name, char ***dst);

int marine_prefs_set_bool(char *module_name, char *pref_name, unsigned char value);
int marine_prefs_get_bool(char *module_name, char *pref_name, unsigned char *dst);

int marine_prefs_set_uint(char *module_name, char *pref_name, unsigned int value);
int marine_prefs_get_uint(char *module_name, char *pref_name, unsigned int *dst);

int marine_prefs_set_str(char *module_name, char *pref_name, char *value);
int marine_prefs_get_str(char *module_name, char *pref_name, char **dst);

#endif //WIRESHARK_MARINE_PREFS_H
