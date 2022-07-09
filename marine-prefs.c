#include <glib.h>

#include "marine-prefs.h"
#include "epan/prefs.h"
#include "epan/prefs-int.h"

WS_DLL_PUBLIC_DEF const int MARINE_PREFS_BAD_MODULE_NAME = -1;
WS_DLL_PUBLIC_DEF const int MARINE_PREFS_BAD_PREF_NAME = -2;
WS_DLL_PUBLIC_DEF const int MARINE_PREFS_BAD_PREF_TYPE = -3;

static int find_module_and_pref(char *module_name, char *pref_name, module_t **module_dst, pref_t **pref_dst);
static unsigned int load_pref_name(pref_t *pref, gpointer user_data);


WS_DLL_PUBLIC int
marine_prefs_list_module_prefs(char *module_name, char ***dst) {
    module_t *module = prefs_find_module(module_name);

    if (module == NULL) {
        return MARINE_PREFS_BAD_MODULE_NAME;
    }

    GPtrArray *pref_names = g_ptr_array_new();
    prefs_pref_foreach(module, &load_pref_name, (gpointer) pref_names);
    *dst = (char **) pref_names->pdata;
    g_ptr_array_free(pref_names, FALSE);
    return 0;
}

WS_DLL_PUBLIC int
marine_prefs_set_bool(char *module_name, char *pref_name, unsigned char value) {
    module_t *module; pref_t *pref;

    int status = find_module_and_pref(module_name, pref_name, &module, &pref);
    if (status != 0) {
        return status;
    }

    if (prefs_get_type(pref) != PREF_BOOL) {
        return MARINE_PREFS_BAD_PREF_TYPE;
    }

    prefs_set_bool_value(pref, value, pref_current);
    prefs_apply(module);
    return 0;
}

WS_DLL_PUBLIC int
marine_prefs_get_bool(char *module_name, char *pref_name, unsigned char *dst) {
    pref_t *pref;

    int status = find_module_and_pref(module_name, pref_name, NULL, &pref);
    if (status != 0) {
        return status;
    }

    if (prefs_get_type(pref) != PREF_BOOL) {
        return MARINE_PREFS_BAD_PREF_TYPE;
    }

    *dst = prefs_get_bool_value(pref, pref_current);
    return 0;
}

WS_DLL_PUBLIC int
marine_prefs_set_uint(char *module_name, char *pref_name, unsigned int value) {
    module_t *module; pref_t *pref;

    int status = find_module_and_pref(module_name, pref_name, &module, &pref);
    if (status != 0) {
        return status;
    }

    if (prefs_get_type(pref) != PREF_UINT) {
        return MARINE_PREFS_BAD_PREF_TYPE;
    }

    prefs_set_uint_value(pref, value, pref_current);
    prefs_apply(module);
    return 0;
}

WS_DLL_PUBLIC int
marine_prefs_get_uint(char *module_name, char *pref_name, unsigned int *dst) {
    pref_t *pref;
    int status = find_module_and_pref(module_name, pref_name, NULL, &pref);
    if (status != 0) {
        return status;
    }

    if (prefs_get_type(pref) != PREF_UINT) {
        return MARINE_PREFS_BAD_PREF_TYPE;
    }

    *dst = prefs_get_uint_value_real(pref, pref_current);
    return 0;
}

WS_DLL_PUBLIC int
marine_prefs_set_str(char *module_name, char *pref_name, char *value) {
    module_t *module; pref_t *pref;
    int status = find_module_and_pref(module_name, pref_name, &module, &pref);
    if (status != 0) {
        return status;
    }

    if (prefs_get_type(pref) != PREF_STRING) {
        return MARINE_PREFS_BAD_PREF_TYPE;
    }

    prefs_set_string_value(pref, value, pref_current);
    prefs_apply(module);
    return 0;
}

WS_DLL_PUBLIC int
marine_prefs_get_str(char *module_name, char *pref_name, char **dst) {
    module_t *module; pref_t *pref;
    int status = find_module_and_pref(module_name, pref_name, &module, &pref);

    if (status != 0) {
        return status;
    }

    if (prefs_get_type(pref) != PREF_STRING) {
        return MARINE_PREFS_BAD_PREF_TYPE;
    }

    *dst = prefs_get_string_value(pref, pref_current);
    return 0;
}

int
find_module_and_pref(char *module_name, char *pref_name, module_t **module_dst, pref_t **pref_dst) {
    module_t *module = prefs_find_module(module_name);
    if (module == NULL) {
        return MARINE_PREFS_BAD_MODULE_NAME;
    }

    pref_t *pref = prefs_find_preference(module, pref_name);
    if (pref == NULL) {
        return MARINE_PREFS_BAD_PREF_NAME;
    }

    if (module_dst != NULL) {
        *module_dst = module;
    }

    if (pref_dst != NULL) {
        *pref_dst = pref;
    }

    return 0;
}

unsigned int
load_pref_name(pref_t *pref, gpointer user_data) {
    GPtrArray *pref_names = (GPtrArray *) user_data;
    const char *pref_name = prefs_get_name(pref);
    g_ptr_array_add(pref_names, (gpointer) pref_name);
    return 0;
}
