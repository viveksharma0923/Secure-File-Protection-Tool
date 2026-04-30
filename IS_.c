#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define MAX_USERS       10
#define MAX_FILES       20
#define MAX_USERNAME    30
#define MAX_PASSWORD    30
#define MAX_FILENAME    100
#define MY_MAX_PATH     200   
#define XOR_KEY         0x5A  
#define USER_DB         "users.dat"
#define ACCESS_LOG      "access_log.txt"
#define ENC_EXTENSION   ".enc"
unsigned int simple_hash(const char *str) {
    unsigned int hash = 0;
    while (*str) {
        hash = (hash * 31 + (unsigned char)*str) % 99991;
        str++;
    }
    return hash;
}

typedef struct {
    char username[MAX_USERNAME];
    unsigned int password_hash;
    int is_admin;    
    int is_active;   /* 1 = active, 0 = deleted */
} User;

typedef struct {
    char filename[MAX_FILENAME];
    char owner[MAX_USERNAME];
    int is_encrypted;
} FileRecord;

/* In-memory DB (saved/loaded from users.dat) */
User users[MAX_USERS];
int  user_count = 0;

/* Currently logged-in user */
char current_user[MAX_USERNAME] = "";
int  current_is_admin = 0;

/* ============================================================
   UTILITY FUNCTIONS
   ============================================================ */

void clear_screen() {
    system("cls");   /* Windows */
}

void pause_screen() {
    printf("\n  Press ENTER to continue...");
    getchar();
    getchar();
}

void print_line(char ch, int len) {
    for (int i = 0; i < len; i++) printf("%c", ch);
    printf("\n");
}

void print_header(const char *title) {
    clear_screen();
    print_line('=', 60);
    printf("    SECURE FILE PROTECTION TOOL\n");
    printf("    JIIT Noida | MCA 2nd Sem | Info Security\n");
    print_line('=', 60);
    printf("  >> %s\n", title);
    print_line('-', 60);
}
void log_event(const char *user, const char *action, const char *detail) {
    FILE *f = fopen(ACCESS_LOG, "a");
    if (!f) return;

    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts) - 1] = '\0'; /* remove newline */

    fprintf(f, "[%s] USER: %-15s | ACTION: %-20s | DETAIL: %s\n",
            ts, user, action, detail);
    fclose(f);
}
void save_users() {
    FILE *f = fopen(USER_DB, "wb");
    if (!f) {
        printf("  [ERROR] Cannot save user database!\n");
        return;
    }
    fwrite(&user_count, sizeof(int), 1, f);
    fwrite(users, sizeof(User), user_count, f);
    fclose(f);
}

void load_users() {
    FILE *f = fopen(USER_DB, "rb");
    if (!f) {
         user_count = 1;
        strcpy(users[0].username, "admin");
        users[0].password_hash = simple_hash("admin123");
        users[0].is_admin = 1;
        users[0].is_active = 1;
        save_users();
        return;
    }
    fread(&user_count, sizeof(int), 1, f);
    fread(users, sizeof(User), user_count, f);
    fclose(f);
}
void xor_encrypt_decrypt(unsigned char *data, long size) {
    for (long i = 0; i < size; i++) {
        data[i] ^= XOR_KEY;
    }
}
int encrypt_file(const char *filepath) {
    FILE *in = fopen(filepath, "rb");
    if (!in) {
        printf("  [ERROR] Cannot open file: %s\n", filepath);
        return 0;
    }
    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    rewind(in);

    if (size == 0) {
        printf("  [ERROR] File is empty!\n");
        fclose(in);
        return 0;
    }
    unsigned char *data = (unsigned char *)malloc(size);
    if (!data) {
        printf("  [ERROR] Memory allocation failed!\n");
        fclose(in);
        return 0;
    }
    fread(data, 1, size, in);
    fclose(in);
    xor_encrypt_decrypt(data, size);
    char enc_path[MY_MAX_PATH];
    snprintf(enc_path, MY_MAX_PATH, "%s%s", filepath, ENC_EXTENSION);
    FILE *out = fopen(enc_path, "wb");
    if (!out) {
        printf("  [ERROR] Cannot create encrypted file!\n");
        free(data);
        return 0;
    }
    fwrite(data, 1, size, out);
    fclose(out);
    free(data);

    printf("  [SUCCESS] File encrypted -> %s\n", enc_path);
    log_event(current_user, "ENCRYPT", filepath);
    return 1;
}
int decrypt_file(const char *enc_filepath) {
    FILE *in = fopen(enc_filepath, "rb");
    if (!in) {
        printf("  [ERROR] Cannot open encrypted file: %s\n", enc_filepath);
        return 0;
    }
    fseek(in, 0, SEEK_END);
    long size = ftell(in);
    rewind(in);
    unsigned char *data = (unsigned char *)malloc(size);
    if (!data) {
        printf("  [ERROR] Memory allocation failed!\n");
        fclose(in);
        return 0;
    }
    fread(data, 1, size, in);
    fclose(in);
    xor_encrypt_decrypt(data, size);
    char dec_path[MY_MAX_PATH];
    strncpy(dec_path, enc_filepath, MY_MAX_PATH);
    int len = strlen(dec_path);
    int ext_len = strlen(ENC_EXTENSION);
    if (len > ext_len && strcmp(dec_path + len - ext_len, ENC_EXTENSION) == 0) {
        dec_path[len - ext_len] = '\0';
    } else {
        strncat(dec_path, ".decrypted", MY_MAX_PATH - strlen(dec_path) - 1);
    }

    FILE *out = fopen(dec_path, "wb");
    if (!out) {
        printf("  [ERROR] Cannot create decrypted file!\n");
        free(data);
        return 0;
    }
    fwrite(data, 1, size, out);
    fclose(out);
    free(data);

    printf("  [SUCCESS] File decrypted -> %s\n", dec_path);
    log_event(current_user, "DECRYPT", enc_filepath);
    return 1;
}
int find_user(const char *username) {
    for (int i = 0; i < user_count; i++) {
        if (users[i].is_active && strcmp(users[i].username, username) == 0)
            return i;
    }
    return -1;
}
int login(const char *username, const char *password) {
    int idx = find_user(username);
    if (idx == -1) {
        log_event(username, "LOGIN_FAIL", "User not found");
        return 0;
    }
    if (users[idx].password_hash != simple_hash(password)) {
        log_event(username, "LOGIN_FAIL", "Wrong password");
        return 0;
    }
    strcpy(current_user, username);
    current_is_admin = users[idx].is_admin;
    log_event(username, "LOGIN_SUCCESS", "");
    return 1;
}

void logout() {
    log_event(current_user, "LOGOUT", "");
    strcpy(current_user, "");
    current_is_admin = 0;
}
int register_user(const char *username, const char *password, int is_admin) {
    if (user_count >= MAX_USERS) {
        printf("  [ERROR] User limit reached!\n");
        return 0;
    }
    if (find_user(username) != -1) {
        printf("  [ERROR] Username already exists!\n");
        return 0;
    }
    strcpy(users[user_count].username, username);
    users[user_count].password_hash = simple_hash(password);
    users[user_count].is_admin = is_admin;
    users[user_count].is_active = 1;
    user_count++;
    save_users();
    log_event(current_user, "REGISTER_USER", username);
    printf("  [SUCCESS] User '%s' registered!\n", username);
    return 1;
}
int has_access(const char *filename) {
    if (current_is_admin) return 1;

    char prefix[MAX_USERNAME + 2];
    snprintf(prefix, sizeof(prefix), "%s_", current_user);
    if (strncmp(filename, prefix, strlen(prefix)) == 0) return 1;

    return 0;
}

void ui_login_screen() {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];

    print_header("LOGIN");
    printf("  Username: ");
    scanf("%29s", username);
    printf("  Password: ");
    scanf("%29s", password);

    if (login(username, password)) {
        printf("\n  [SUCCESS] Welcome, %s! (%s)\n",
               current_user, current_is_admin ? "Admin" : "User");
    } else {
        printf("\n  [FAILED] Invalid username or password!\n");
        pause_screen();
    }
}

void ui_encrypt_menu() {
    char filepath[MY_MAX_PATH];

    print_header("ENCRYPT A FILE");
    printf("  Enter full file path (e.g., C:\\test\\myfile.txt):\n  > ");
    scanf(" ");
    fgets(filepath, MY_MAX_PATH, stdin);
    filepath[strcspn(filepath, "\n")] = '\0';

    char *fname = strrchr(filepath, '\\');
    if (!fname) fname = filepath;
    else fname++;

    if (!has_access(fname) && !current_is_admin) {
        printf("\n  [ACCESS DENIED] You don't have permission for this file.\n");
        printf("  Tip: Name your file as: %s_yourfile.txt\n", current_user);
        log_event(current_user, "ACCESS_DENIED", filepath);
        pause_screen();
        return;
    }

    encrypt_file(filepath);
    pause_screen();
}

void ui_decrypt_menu() {
    char filepath[MY_MAX_PATH];

    print_header("DECRYPT A FILE");
    printf("  Enter full path of encrypted file (e.g., C:\\test\\myfile.txt.enc):\n  > ");
    scanf(" ");
    fgets(filepath, MY_MAX_PATH, stdin);
    filepath[strcspn(filepath, "\n")] = '\0';

    char *fname = strrchr(filepath, '\\');
    if (!fname) fname = filepath;
    else fname++;

    if (!has_access(fname) && !current_is_admin) {
        printf("\n  [ACCESS DENIED] You don't have permission for this file.\n");
        log_event(current_user, "ACCESS_DENIED", filepath);
        pause_screen();
        return;
    }

    decrypt_file(filepath);
    pause_screen();
}

void ui_view_log() {
    if (!current_is_admin) {
        printf("\n  [ACCESS DENIED] Only admins can view logs!\n");
        pause_screen();
        return;
    }

    print_header("ACCESS LOG");
    FILE *f = fopen(ACCESS_LOG, "r");
    if (!f) {
        printf("  No log entries yet.\n");
        pause_screen();
        return;
    }

    char line[300];
    int count = 0;
    while (fgets(line, sizeof(line), f)) {
        printf("  %s", line);
        count++;
    }
    fclose(f);

    if (count == 0) printf("  Log is empty.\n");
    pause_screen();
}

void ui_register_user() {
    if (!current_is_admin) {
        printf("\n  [ACCESS DENIED] Only admins can register users!\n");
        pause_screen();
        return;
    }

    char uname[MAX_USERNAME], pwd[MAX_PASSWORD];
    int role;

    print_header("REGISTER NEW USER");
    printf("  New Username: ");
    scanf("%29s", uname);
    printf("  Password:     ");
    scanf("%29s", pwd);
    printf("  Role (0=Normal User, 1=Admin): ");
    scanf("%d", &role);

    register_user(uname, pwd, role ? 1 : 0);
    pause_screen();
}

void ui_list_users() {
    if (!current_is_admin) {
        printf("\n  [ACCESS DENIED] Only admins can list users!\n");
        pause_screen();
        return;
    }

    print_header("REGISTERED USERS");
    printf("  %-5s %-20s %-10s\n", "No.", "Username", "Role");
    print_line('-', 40);
    for (int i = 0; i < user_count; i++) {
        if (users[i].is_active) {
            printf("  %-5d %-20s %-10s\n",
                   i + 1,
                   users[i].username,
                   users[i].is_admin ? "Admin" : "User");
        }
    }
    pause_screen();
}

void ui_change_password() {
    char old_pwd[MAX_PASSWORD], new_pwd[MAX_PASSWORD];

    print_header("CHANGE PASSWORD");
    printf("  Current Password: ");
    scanf("%29s", old_pwd);

    int idx = find_user(current_user);
    if (idx == -1 || users[idx].password_hash != simple_hash(old_pwd)) {
        printf("\n  [ERROR] Incorrect current password!\n");
        pause_screen();
        return;
    }

    printf("  New Password:     ");
    scanf("%29s", new_pwd);
    users[idx].password_hash = simple_hash(new_pwd);
    save_users();
    log_event(current_user, "CHANGE_PASSWORD", "");
    printf("\n  [SUCCESS] Password changed!\n");
    pause_screen();
}

void ui_about() {
    print_header("ABOUT THIS PROJECT");
    printf("\n");
    printf("  Project  : Secure File Protection Tool\n");
    printf("  Course   : Information Security (24M11CA119)\n");
    printf("  Program  : MCA 2nd Sem, 2025-2027\n");
    printf("  College  : JIIT Noida\n\n");
    printf("  Team Members:\n");
    printf("    - Aadit Sharma  (992510170080) - Encryption & Auth\n");
    printf("    - Vivek Sharma  (992510170081) - User Interface\n");
    printf("    - Shivam Singh  (992510170082) - Integration & Testing\n\n");
    printf("  Encryption : XOR Cipher (Symmetric Encryption)\n");
    printf("  Auth       : Hash-based Password Verification\n");
    printf("  Access Ctrl: Role-based (Admin / Normal User)\n\n");
    printf("  CIA Triad:\n");
    printf("    Confidentiality -> XOR Encryption of files\n");
    printf("    Integrity       -> File is unreadable without key\n");
    printf("    Availability    -> Only authorized users can access\n");
    pause_screen();
}
void main_menu() {
    int choice;

    while (1) {
        print_header(current_is_admin ? "MAIN MENU [Admin]" : "MAIN MENU [User]");
        printf("  Logged in as: %s\n\n", current_user);
        printf("  1. Encrypt a File\n");
        printf("  2. Decrypt a File\n");
        printf("  3. Change My Password\n");

        if (current_is_admin) {
            printf("  4. Register New User\n");
            printf("  5. List All Users\n");
            printf("  6. View Access Log\n");
        }

        printf("  7. About Project\n");
        printf("  0. Logout\n\n");
        printf("  Enter choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: ui_encrypt_menu();     break;
            case 2: ui_decrypt_menu();     break;
            case 3: ui_change_password();  break;
            case 4: if (current_is_admin) ui_register_user(); break;
            case 5: if (current_is_admin) ui_list_users();    break;
            case 6: if (current_is_admin) ui_view_log();      break;
            case 7: ui_about();            break;
            case 0:
                logout();
                return;
            default:
                printf("\n  [ERROR] Invalid choice!\n");
                pause_screen();
        }
    }
}
int main() {
    load_users();

    while (1) {
        print_header("WELCOME");
        printf("  1. Login\n");
        printf("  0. Exit\n\n");
        printf("  Enter choice: ");

        int choice;
        scanf("%d", &choice);

        if (choice == 0) {
            printf("\n  Goodbye! Stay Secure.\n\n");
            break;
        } else if (choice == 1) {
            ui_login_screen();
            if (strlen(current_user) > 0) {
                main_menu();
            }
        } else {
            printf("\n  Invalid choice!\n");
        }
    }

    return 0;
}