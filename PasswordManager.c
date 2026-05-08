#include "PasswordManager.h"

static const char PM_DEFAULT_KEY[] = "change_this_key";
static char *g_encryption_key = NULL;

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//Base64 encoding
static char *pm_base64_encode(const unsigned char *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        unsigned a = data[i++];
        unsigned b = (i < len) ? data[i++] : 0;
        unsigned c = (i < len) ? data[i++] : 0;
        unsigned triple = (a << 16) | (b << 8) | c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i - 1 <= len) ? b64_table[(triple >> 6) & 0x3F] : '=';
        out[j++] = (i <= len) ? b64_table[triple & 0x3F] : '=';
    }
    out[out_len] = '\0';
    return out;
}

//Base64 decoding
static unsigned char *pm_base64_decode(const char *b64, size_t *out_len) {
    if (b64 == NULL || out_len == NULL) return NULL;
    size_t blen = strlen(b64);
    if (blen % 4 != 0) return NULL;

    static int rev[256];
    static int rev_init = 0;
    if (!rev_init) {
        for (int i = 0; i < 256; ++i) rev[i] = -1;
        for (int i = 0; i < 64; ++i) rev[(unsigned char)b64_table[i]] = i;
        rev_init = 1;
    }

    size_t out_capacity = (blen / 4) * 3;
    unsigned char *out = malloc(out_capacity);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    while (i < blen) {
        int v[4];
        for (int k = 0; k < 4; ++k) {
            char ch = b64[i++];
            if (ch == '=') v[k] = -2; else v[k] = rev[(unsigned char)ch];
            if (v[k] == -1) { free(out); return NULL; }
        }

        unsigned triple = ((v[0] < 0 ? 0 : v[0]) << 18) | ((v[1] < 0 ? 0 : v[1]) << 12) | ((v[2] < 0 ? 0 : v[2]) << 6) | (v[3] < 0 ? 0 : v[3]);

        out[j++] = (triple >> 16) & 0xFF;
        if (v[2] != -2) out[j++] = (triple >> 8) & 0xFF;
        if (v[3] != -2) out[j++] = triple & 0xFF;
    }

    *out_len = j;
    return out;
}

int pm_set_encryption_key(const char *key) {
    if (key == NULL) return -1;
    free(g_encryption_key);
    g_encryption_key = strdup(key);
    return (g_encryption_key == NULL) ? -1 : 0;
}

void pm_clear_encryption_key(void) {
    free(g_encryption_key);
    g_encryption_key = NULL;
}

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
        free(pm->entries[i].category);
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
int pm_update_entry(PasswordManager *pm, const PasswordEntry *entry){
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
            free(pm->entries[i].category);
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
    PasswordEntry *matches = malloc(pm->count * sizeof(PasswordEntry)); 
    if(matches == NULL){
        return NULL; 
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
int pm_save_to_file_csv(const PasswordManager *pm, const char *path){
    FILE *f = fopen(path, "w");
    if(f == NULL){
        return -1;
    }
    const char *key = g_encryption_key ? g_encryption_key : PM_DEFAULT_KEY;
    
    /* Write digest header for key verification */
    char *digest = calculate_digest(key);
    if (digest == NULL) {
        fclose(f);
        return -1;
    }
    fprintf(f, "DIGEST:%s\n", digest);
    free(digest);
    
    /* Write entries with encrypted passwords */
    for(int i=0; i<pm->count; i++){
        char *enc = pm_encrypt_password(pm->entries[i].password);
        if (enc == NULL) {
            fclose(f);
            return -1;
        }
        fprintf(f, "%s,%s,%s,%s,%s,%s,%lu,%lu\n",
            pm->entries[i].id, pm->entries[i].service, pm->entries[i].username,
            enc, pm->entries[i].url, pm->entries[i].notes,
            pm->entries[i].created_at, pm->entries[i].updated_at);
        free(enc);
    }
    fclose(f);
    return 0;
}

//loading entries from a file in CSV format
int pm_load_from_file_csv(PasswordManager *pm, const char* path){
    FILE *F = fopen(path, "r");
    if(F==NULL){
        return -1;
    }
    const char *key = g_encryption_key ? g_encryption_key : PM_DEFAULT_KEY;
    char line[1024];
    int first_line = 1;
    while(fgets(line, sizeof(line), F)){
        /* Check digest on first line */
        if (first_line) {
            first_line = 0;
            if (strncmp(line, "DIGEST:", 7) == 0) {
                char *stored_digest = line + 7;
                size_t dlen = strlen(stored_digest);
                if (dlen > 0 && stored_digest[dlen - 1] == '\n') {
                    stored_digest[dlen - 1] = '\0';
                }
                char *calc_digest = calculate_digest(key);
                if (calc_digest == NULL) {
                    fclose(F);
                    return -1;
                }
                /* Compare digests */
                int match = (strcmp(stored_digest, calc_digest) == 0) ? 1 : 0;
                free(calc_digest);
                if (!match) {
                    fclose(F);
                    return -1; /* key mismatch */
                }
                continue; 
            }
        }
        
        PasswordEntry entry; 
        char *dec_password = NULL;
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
        /* token contains encrypted base64 password */
        dec_password = pm_decrypt_password(token);
        if (dec_password == NULL) dec_password = strdup("");
        entry.password = dec_password;
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
        entry.updated_at = strtoul(token, NULL, 10); //strtoul converts string to unsigned long
        pm_add_entry(pm, &entry); //add the entry to the password manager
    }
    fclose(F);
    return 0;
}

/* Encrypts a plaintext password using XOR with the runtime key (or default) and returns HEX string (malloc'd) */
char *pm_encrypt_password(const char *plain_password) {
    if (plain_password == NULL) return NULL;
    const char *key = g_encryption_key ? g_encryption_key : PM_DEFAULT_KEY;
    size_t plen = strlen(plain_password);
    size_t klen = strlen(key);
    unsigned char *tmp = malloc(plen);
    if (!tmp) return NULL;
    for (size_t i = 0; i < plen; ++i) tmp[i] = (unsigned char)(plain_password[i] ^ key[i % klen]);
    char *b64 = pm_base64_encode(tmp, plen);
    free(tmp);
    return b64;
}

/* Decrypts a HEX string produced by pm_encrypt_password and returns plaintext (malloc'd) */
char *pm_decrypt_password(const char *encrypted_password) {
    if (encrypted_password == NULL) return NULL;
    const char *key = g_encryption_key ? g_encryption_key : PM_DEFAULT_KEY;
    size_t decoded_len = 0;
    unsigned char *decoded = pm_base64_decode(encrypted_password, &decoded_len);
    if (!decoded) return NULL;
    size_t klen = strlen(key);
    char *plain = malloc(decoded_len + 1);
    if (!plain) { free(decoded); return NULL; }
    for (size_t i = 0; i < decoded_len; ++i) plain[i] = (char)(decoded[i] ^ key[i % klen]);
    plain[decoded_len] = '\0';
    free(decoded);
    return plain;
}

/* Calculate XOR digest over 32 bytes*/
char *calculate_digest(const char *password) {
    if (password == NULL) return NULL;
    unsigned char digest[32] = {0};
    size_t plen = strlen(password);
    /* XOR each byte of password into digest[i % 32] */
    for (size_t i = 0; i < plen; ++i) {
        digest[i % 32] ^= (unsigned char)password[i];
    }
    return pm_base64_encode(digest, 32);
}

char* AES_encryption(const char* text, const char* key) {
    AES_KEY enc_key;
    AES_set_encrypt_key((const unsigned char*)key, 128, &enc_key);
    size_t text_len = strlen(text);
    size_t padded_len = ((text_len + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; //we use it for padding the plaintext to a multiple of AES block size
    unsigned char *padded_text = calloc(1, padded_len);
    if (!padded_text) return NULL;
    memcpy(padded_text, text, text_len);
    unsigned char *encrypted = malloc(padded_len);
    if(!encrypted) {
        free(padded_text);
        return NULL;
    }
    for(size_t i=0; i<padded_len; i+=AES_BLOCK_SIZE){
        AES_encrypt(padded_text + i, encrypted + i, &enc_key); //we are encrypting each block of the padded plaintext and storing in the encrypted buffer.
    }
    free(padded_text);
    return (char*)encrypted;
}

char* AES_decryption(const char* cipher, const char* key){
    AES_KEY dec_key;
    AES_set_decrypt_key((const unsigned char*)key, 128, &dec_key);
    size_t cipher_len = strlen(cipher);
    unsigned char *decrypted = malloc(cipher_len);
    if(!decrypted) return NULL;
    for(size_t i=0; i<cipher_len; i+=AES_BLOCK_SIZE){
        AES_decrypt((const unsigned char*)cipher + i, decrypted + i, &dec_key); //we are decrypting each block of the cipher and storing in the decrypted buffer.
    }
    free((void*)cipher); 
    return (char*)decrypted;
}

char* password_valutation(const char* password){
    size_t p_length = strlen(password);
    int has_upper = 0, has_lower = 0, has_digit = 0, has_symbol = 0;
    for(size_t i=0; i<p_length; i++){
        if(password[i] >= 'A' && password[i]<='Z') has_upper=1;
        else if(password[i] >= 'a' && password[i]<='z') has_lower=1;
        else if(password[i] >= '0' && password[i]<='9') has_digit=1;
        else has_symbol=1;
    }

    if(p_length >= 8 && has_upper && has_lower && has_digit && has_symbol) {
        return "Strong";
    } else {
        return "Weak";
    }
}

int check_password_reusage(const PasswordManager *pm, const char* password){
    for(int i=0; i<pm->count; i++){
        if(strcmp(pm->entries[i].password, password) == 0){
            return 1;
        }
    }
    return 0;
}

void category_filter(const PasswordManager *pm, const char* category, size_t *out_count){
    size_t match_count = 0;
    for(size_t i=0; i<pm->count; i++){
        if(strcmp(pm->entries[i].category, category) == 0){
            match_count++;
            printf("ID: %s\nService: %s\nUsername: %s\nURL: %s\nCreated At: %lu\nUpdated At: %lu\n\n",
                pm->entries[i].id, pm->entries[i].service, pm->entries[i].username,
                pm->entries[i].url, pm->entries[i].created_at, pm->entries[i].updated_at);
        }
    }
    *out_count = match_count;
}


PasswordEntry *pm_entry_init(void){
    PasswordEntry *entry = malloc(sizeof(PasswordEntry));
    if(entry == NULL) return NULL;
    entry->id = NULL;
    entry->service = NULL;
    entry->username = NULL;
    entry->password = NULL;
    entry->url = NULL;
    entry->notes = NULL;
    entry->category = NULL;
    entry->created_at = 0;
    entry->updated_at = 0;
    return entry;
}

int export_to_json(const PasswordManager *pm, const char *path){
    FILE *f = fopen(path, "w");
    if(f == NULL){
        return -1;
    }
    fprintf(f, "{\n  \"entries\": [\n");
    for(int i=0; i<pm->count; i++){
        fprintf(f, "    {\n");
        fprintf(f, "      \"id\": \"%s\",\n", pm->entries[i].id);
        fprintf(f, "      \"service\": \"%s\",\n", pm->entries[i].service);
        fprintf(f, "      \"username\": \"%s\",\n", pm->entries[i].username);
        fprintf(f, "      \"password\": \"%s\",\n", pm->entries[i].password);
        fprintf(f, "      \"url\": \"%s\",\n", pm->entries[i].url);
        fprintf(f, "      \"notes\": \"%s\",\n", pm->entries[i].notes);
        fprintf(f, "      \"category\": \"%s\",\n", pm->entries[i].category);
        fprintf(f, "      \"created_at\": %lu,\n", pm->entries[i].created_at);
        fprintf(f, "      \"updated_at\": %lu\n", pm->entries[i].updated_at);
        if(i < pm->count - 1){
            fprintf(f, "    },\n");
        } else {
            fprintf(f, "    }\n");
        }
    }
    fprintf(f, "  ]\n}");
    fclose(f);
    return 0;
}

int import_from_json(PasswordManager *pm, const char *path){
    FILE *f = fopen(path, "r");
    if(f == NULL){
        return -1;
    }
    char buffer[1024];
    fgets(buffer, sizeof(buffer), f);
    if(strncmp(buffer, "{", 1) != 0){
        fclose(f);
        return -1;
    }
    while(fgets(buffer, sizeof(buffer), f)){
        if(strncmp(buffer, "}", 1) == 0){
            break;
        }
        if(strstr(buffer, "\"id\":")){
            PasswordEntry entry; 
            char *token = strtok(buffer, "\"");
            token = strtok(NULL, "\"");
            entry.id = strdup(token);
            token = strtok(NULL, "\"");
            token = strtok(NULL, "\"");
            entry.service = strdup(token);
            token = strtok(NULL, "\"");
            token = strtok(NULL, "\"");
            entry.username = strdup(token);
            token = strtok(NULL, "\"");
            token = strtok(NULL, "\"");
            entry.password = strdup(token);
            token = strtok(NULL, "\"");
            token = strtok(NULL, "\"");
            entry.url = strdup(token);
            token = strtok(NULL, "\"");
            token = strtok(NULL, "\"");
            entry.notes = strdup(token);
            token = strtok(NULL, "\"");
            token = strtok(NULL, "\"");
            entry.category = strdup(token);
            token = strtok(NULL, ":");
            token = strtok(NULL, ",");
            entry.created_at = strtoul(token, NULL, 10);
            token = strtok(NULL, ":");
            token = strtok(NULL, ",");
            entry.updated_at = strtoul(token, NULL, 10);
            pm_add_entry(pm, &entry);
        }
    }
    fclose(f);
    return 0;
}


// Load from file - automatically detects format by extension
int pm_load_file(PasswordManager *pm, const char *path){
    if (strstr(path, ".json") != NULL) {
        return import_from_json(pm, path);
    }
    return pm_load_from_file_csv(pm, path);
}

// Save to file - automatically detects format by extension
int pm_save_file(const PasswordManager *pm, const char *path){
    if (strstr(path, ".json") != NULL) {
        return export_to_json(pm, path);
    }
    return pm_save_to_file_csv(pm, path);
}