#ifndef PASSWORD_MANAGER_H
#define PASSWORD_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h> 

typedef struct PasswordEntry {
    char *id; 
    char *service; 
    char *username; 
    char *password;
    char *url; 
    char *notes; 
    char *category;
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
int pm_set_encryption_key(const char *key);
void pm_clear_encryption_key(void);
char *pm_encrypt_password(const char *plain_password);
char *pm_decrypt_password(const char *encrypted_password);

/* persistence */
int pm_save_to_file(const PasswordManager *pm, const char *path);
int pm_load_from_file(PasswordManager *pm, const char *path);

char* calculate_digest(const char* password);
char* AES_encryption(const char* text, const char* key);
char* AES_decryption(const char* cipher, const char* key);

char *password_valutation(const char *password);
int check_password_reusage(const PasswordManager *pm, const char* password);
void category_filter(const PasswordManager *pm, const char* category, size_t *out_count);

PasswordEntry *pm_entry_init(void);

#endif