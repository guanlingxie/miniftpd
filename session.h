#ifndef SESSION_H__
#define SESSION_H__

#include "common.h"

typedef struct session{
    uid_t uid;
    int ctrl_fd;

    char cmdline[MAX_COMMAND_LINE];
    char cmd[MAX_COMMAND];
    char arg[MAX_ARG];

    struct sockaddr_in *port_addr;
    int pasv_listen_fd;
    int data_fd;
    int data_process;

    unsigned int bw_upload_rate_max;
    unsigned int bw_download_rate_max;

    int parent_fd;
    int child_fd;

    int is_ascii;
    long long restart_pos;
    int abor_received;
    char *rnfr_name;
}session_t;
void begin_session(session_t *sess);

#endif