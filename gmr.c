#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <shadow.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <pwd.h>
#include <time.h>
#include <fcntl.h>
#include <crypt.h>
#include <sys/stat.h>

#define ROOTERS "/etc/rooters.txt"
#define LOG "/usr/share/gmr.log"

void llog(const char *msg) {
    FILE *fptr = fopen(LOG, "a");
    fprintf(fptr, "MSG: %s\n", msg);
    fclose(fptr);
}

typedef struct passwd passwd;
int CheckPassword( const char *user, const char *password )
{
    passwd *passwdEntry = getpwnam( user );
    if ( !passwdEntry )
    {
        printf( "User '%s' doesn't exist\n", user );
        return 1;
    }
    
    struct spwd *shadowEntry = getspnam(user);
    if (!shadowEntry) {
        printf("Cannot access shadow entry for user '%s'\n", user);
        return 1;
    }

    const char *hashedPassword = crypt(password, shadowEntry->sp_pwdp);
    if (!hashedPassword || strcmp(hashedPassword, shadowEntry->sp_pwdp) != 0) {
        printf("Incorrect password for user '%s'\n", user);
        return 1;
    }

    return 0;
}

void run_bash() {
    __uid_t uid = getuid();
    __uid_t gid = getgid();
    setuid(0);
    setgid(0);
    system("/bin/bash");
    setgid(gid);
    setuid(uid);
}

void run_app(int Argc, char** Argv) {
    char **Argv1 = malloc(sizeof(char*)*(Argc+1));
    for (int i = 0; i < Argc; i++) {
        Argv1[i] = Argv[i];
    }
    Argv1[Argc] = NULL;
    __uid_t uid = getuid();
    __uid_t gid = getgid();
    setuid(0);
    setgid(0);
    execv(Argv[0], Argv1);
    setgid(gid);
    setuid(uid);
}

struct acs_spliter {
    char *s;
    int sz;
    int p;
    int end;
};
typedef struct acs_spliter acs_spliter;



char *acs_cp(char *a)
{
    int s = strlen(a);
    char *o = malloc(s+1);
    memcpy(o, a, s);
    o[s] = 0;
    return o;
}
char *acs_milloc(char *str)
{
    char* o = acs_cp(str);
    free(str);
    return o;
}

acs_spliter* acs_spliter_init(char *str)
{
    acs_spliter* o = malloc(sizeof(acs_spliter)*1);
    o->s = str;
    o->p = 0;
    o->sz = strlen(str);
    o->end = 0;
    return o;
}

char *acs_spliter_char(acs_spliter *self, char split)
{
    char *o = malloc(self->sz+1);
    memset(o, 0, self->sz+1);
    int i = self->p;
    for (;;) {
        if (i >= self->sz) {
            self->end = 1;
            return acs_milloc(o);
        }
        if (self->s[i] == split) {
            i++;
            break;
        }
        o[i-self->p] = self->s[i];
        i++;
    }
    self->p = i;
    return acs_milloc(o);
}

char isroot(char *user) {
    char *rooters = malloc(9900);
    memset(rooters, 0, 9900);
    FILE *fptr = fopen(ROOTERS, "r");
    fread(rooters, 1, 9900, fptr);
    fclose(fptr);
    acs_spliter *rootspliter = acs_spliter_init(rooters);

    char yes = 0;

    while (rootspliter->end == 0) {
        char *u = acs_spliter_char(rootspliter, '\n');
        if (!strcmp(u, user)) {
            yes = 1;
            break;
        }
        free(u);
    }
    free(rootspliter);
    free(rooters);
    return yes;
}

char *sum(const char *c1, const char *c2) {
    int l = strlen(c1)+strlen(c2)+1;
    char *c = malloc(l);
    sprintf(c, "%s%s", c1, c2);
    return c;
}

int main(int argc, char **argv) {
    char *user = getpwuid(getuid())->pw_name;
    if (!isroot(user)) {
        printf("You are not in rooters.\n");
        return 1;
    }
    time_t t = time(NULL);
        char *ca1 = "user (";
        char *ca2 = user;
        char *ca3 = ") open gmr";
        char *Ca1 = sum(ca1, ca2);
        char *Ca2 = sum(Ca1, ca3);
        llog(Ca2);
        free(Ca1);
        free(Ca2);
    char *fn = sum("/etc/gmr_timer_", user);
    char *pass = malloc(500);
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    if (access(fn, F_OK)==0) {
        chmod(fn, 0600);
        FILE *fptr = fopen(fn, "r");
        time_t last;
        fread(&last, sizeof(time_t), 1, fptr); 
        fclose(fptr);
        if (t-last < 180) {
            fptr = fopen(fn, "w");
            fwrite(&t, sizeof(time_t), 1, fptr);
            fclose(fptr);
                ca1 = "user (";
                ca2 = user;
                ca3 = ") has the ticket";
                Ca1 = sum(ca1, ca2);
                Ca2 = sum(Ca1, ca3);
                llog(Ca2);
                free(Ca1);
                free(Ca2);
            if (argc == 1)
                run_bash();
            else
                run_app(argc-1, &argv[1]);
            free(fn);
            return 0;
        }
    }
    for (int i = 0; i < 3; i++) {
        printf("Write passwd for %s:", user);
        fflush(stdout);
        
        term.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &term);  
        ssize_t len = read(0, pass, 500);
        term.c_lflag |= (ECHO);
        printf("\n");
        if (len > 0) {
            if (pass[len-1] == '\n')
                pass[len-1] = 0;
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &term);  
        if (!CheckPassword(user, pass)) {
            chmod(fn, 0600);
            FILE *fptr = fopen(fn, "w");
            fwrite(&t, sizeof(time_t), 1, fptr);
            fclose(fptr);
            if (argc == 1)
                run_bash();
            else
                run_app(argc-1, &argv[1]);
            break;
        }
    }
    free(fn);
}