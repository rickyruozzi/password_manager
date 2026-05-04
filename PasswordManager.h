#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdlib.h>

typedef struct PasswordEntry {
    char *id; 
    char *service; 
    char *username; 
    char *password;
    char *url; 
    char *notes; 
    uint64_t created_at; 
    uint64_t updated_at; 
} PasswordEntry;

typedef struct passwordFilter {
    char *service; 
    char *username; 
    char *text;
} PasswordFilter;

typedef struct PasswordManager {
    PasswordEntry *entries;
    size_t count;
    size_t capacity;
} PasswordManager;

void pm_init(PasswordManager *pm);
void pm_free(PasswordManager *pm);

/* credentials management */
int pm_add_entry(PasswordManager *pm, const PasswordEntry *entry);
int pm_update_entry(PasswordManager *pm, const PasswordEntry *entry);
int pm_remove_entry(PasswordManager *pm, const char *id);
PasswordEntry *pm_get_entry_by_id(PasswordManager *pm, const char *id);

/* search and listing */
PasswordEntry *pm_list_entries(const PasswordManager *pm, size_t *out_count);
PasswordEntry *pm_search_entries(const PasswordManager *pm, const PasswordFilter *filter, size_t *out_count);

/* utilities */
char *pm_generate_password(size_t length, int use_symbols);

/* persistence */
int pm_save_to_file(const PasswordManager *pm, const char *path);
int pm_load_from_file(PasswordManager *pm, const char *path);


#endif