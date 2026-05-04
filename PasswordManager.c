#include "PasswordManager.h"

void pm_init(PasswordManager *pm) {
    pm->entries = NULL;
    pm->count = 0;
    pm->capacity = 0;
}

void pm_free(PasswordManager *pm){
    for(int i=0; i<pm->count; i++){
        free(pm->entries[i].id);
        free(pm->entries[i].service);
        free(pm->entries[i].username);
        free(pm->entries[i].password);
        free(pm->entries[i].url);
        free(pm->entries[i].notes);
    }
    free(pm->entries);
    pm->entries = NULL;
    pm->count = 0;
}


// entry insertion into entries array
int pm_add_entry(PasswordManager *pm, const PasswordEntry *entry){
    if(pm->count >= pm->capacity){
        size_t new_capacity = (pm->capacity == 0) ? 4 : pm->capacity * 2; 
        passwordEntry* new_entries = realloc(pm->entries, new_capacity * sizeof(passwordEntry)); 
        if(new_entries == NULL){
            return -1; 
        }
        pm->entries = new_entries; 
        pm->capacity = new_capacity; 
    }
    pm ->entries[pm->count++] = *entry; 
    return 0;
}

//updating entry by id
int pm_update_entry(PasswordManager *pm, const passwordEntry *entry){
    for(int i=0; i<pm->count; i++){
        if(strcmp(pm->entries[i].id, entry->id) == 0){
            pm->entries[i] = *entry;
            return 0;
        }
    }
    return -1;
}

//removing entry by id
int pm_remove_entry(PasswordManager *pm, const char *id){
    for(int i=0; i<pm->count; i++){
        if(strcmp(pm->entries[i].id, id) == 0){
            free(pm->entries[i].id);
            free(pm->entries[i].service);
            free(pm->entries[i].username);
            free(pm->entries[i].password);
            free(pm->entries[i].url);
            free(pm->entries[i].notes);
            for(int j=i; j<pm->count-1; j++){
                pm->entries[j] = pm->entries[j+1];
            }
            pm->count--;
            return 0;
        }
    }
    return -1;
}

//retrieving entry by id
PasswordEntry *pm_get_entry_by_id(PasswordManager *pm, const char *id){
    for(int i=0; i<pm->count; i++){
        if(strcmp(pm->entries[i].id, id) == 0){
            return &pm->entries[i];
        }
    }
    return NULL;
}

//listing all entries
PasswordEntry *pm_list_entries(const PasswordManager *pm, size_t *out_count){
    if(pm->count == 0){
        *out_count = 0;
        return NULL;
    }
    for(int i=0; i<pm->count; i++){
        printf("ID: %s\nService: %s\nUsername: %s\nURL: %s\nCreated At: %lu\nUpdated At: %lu\n\n",
            pm->entries[i].id, pm->entries[i].service, pm->entries[i].username,
            pm->entries[i].url, pm->entries[i].created_at, pm->entries[i].updated_at);
    }
    *out_count = pm->count;
    return pm->entries;
}

//searching entries by filter
PasswordEntry *pm_search_entries(const PasswordManager *pm, const PasswordFilter *filter, size_t *out_count){
    size_t match_count = 0; 
    PasswordEntry *matches = malloc(pm->count * sizeof(PasswordEntry)){
        if(matches == NULL){
            return NULL; 
        }
    }
    for(int i=0; i<pm->count; i++){
        int service_match = (filter->service == NULL) || (strcmp(pm->entries[i].service, filter->service) == 0);
        int username_match = (filter->username == NULL) || (strcmp(pm->entries[i].username, filter->username) == 0);
        int text_match = (filter->text == NULL) || 
            (strstr(pm->entries[i].service, filter->text) != NULL) ||
            (strstr(pm->entries[i].username, filter->text) != NULL) ||
            (strstr(pm->entries[i].url, filter->text) != NULL) ||
            (strstr(pm->entries[i].notes, filter->text) != NULL);
        
        if(service_match && username_match && text_match){
            matches[match_count++] = pm->entries[i];
        }
    }
    *out_count = match_count;
    return matches;
}

//generate a random password of specified length and complexity, it uses symbols only if it is specified
char *pm_generate_password(size_t length, int use_symbols){
    const char* charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const char* symbols="!@#$%^&*()-_=+[]{}|;:,.<>?";
    size_t charsert_len = strlen(charset);
    size_t symbols_len = strlen(symbols);
    char *password = malloc(length + 1);
    if(password == NULL){
        return NULL;
    }

    for(int i=0; i<length; i++){
        if(use_symbols && (rand() % 4 == 0)){ //it uses symbols with a 25% chance
            password[i] = symbols[rand() % symbols_len]; //it uses a random symbol from the symble set
        } else {
            password[i] = charset[rand() % charsert_len]; //or it uses a random character from the charset
        }
    }
    password[length] = '\0';
    return password;
}

//saving entries to a file in csv format
int pm_save_to_file(const PasswordManager *pm, const char *path){
    FILE *f = fopen(path, "w");
    if(f == NULL){
        return -1;
    }
    for(int i=0; i<pm->count; i++){
        fprintf(f, "%s,%s,%s,%s,%s,%s,%lu,%lu\n",
            pm->entries[i].id, pm->entries[i].service, pm->entries[i].username,
            pm->entries[i].password, pm->entries[i].url, pm->entries[i].notes,
            pm->entries[i].created_at, pm->entries[i].updated_at);
    }
    fclose(f);
    return 0;
}

//loading entries from a file
int pm_load_from_file(PasswordManager *pm, const char* path){
    FILE *F = fopen(path, "r");
    if(F==NULL){
        return -1;
    }
    char line[1024];
    while(fgets(line, sizeof(line), F)){
        PasswordEntry entry; 
        char *token = strtok(line, ",");
        if(token == NULL) continue; 
        entry.id = strdup(token); //strdup allocates memory and copies the string
        token = strtok(NULL, ",");
        if(token == NULL) continue;
        entry.service = strdup(token);
        token = strtok(NULL, ",");
        if(token == NULL) continue;
        entry.username = strdup(token);
        token = strtok(NULL, ",");
        if(token == NULL) continue;
        entry.password = strdup(token);
        token = strtok(NULL, ",");
        if(token == NULL) continue;
        entry.url = strdup(token);
        token = strtok(NULL, ",");
        if(token == NULL) continue;
        entry.notes = strdup(token);
        token = strtok(NULL, ",");
        if(token == NULL) continue;
        entry.created_at = strtoul(token, NULL, 10); //strtoul converts string to unsigned long
        token = strtok(NULL, ",");
        if(token == NULL) continue;
        entry.updated_at = strtoul(token, NULL, 10);
        pm_add_entry(pm, &entry); //add the entry to the password manager
    }
    fclose(F);
    return 0;
}

//TODO: PASSWORD ENCRYPTION, FILE ENCRYPTION, ERROR HANDLING, MEMORY MANAGEMENT, TESTING, DOCUMENTATION, SPECIAL CHARACTER PROBLEM WITH STRTOK.