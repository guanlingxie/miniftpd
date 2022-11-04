#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"
#include "ftpcodes.h"

extern session_t *p_sess;
static unsigned int active_clients;

void handle_sigchld(int);
int main(void)
{
    parseconf_load_file(MINIFTP_CONF);

    if(getuid() != 0)
    {
        fprintf(stderr,"miniftpd : must be started as root \n");
        exit(EXIT_FAILURE);
    }

    
    session_t sess = {
        0,-1,"","","",NULL,-1,-1,
        0,0,0,
        -1,-1,0,0,0,NULL
    };
    p_sess = &sess;
    sess.bw_upload_rate_max = tunable_upload_max_rate;
    sess.bw_download_rate_max = tunable_download_max_rate;
    signal(SIGCHLD,handle_sigchld);
    int listenfd = tcp_server(tunable_listen_address,tunable_listen_port);
    int conn;
    pid_t pid;
    while(1)
    {
        conn = accept_timeout(listenfd,NULL,0);
        printf("accept is already \n");
        if(conn == -1)
            ERR_EXIT("accept_timeout");
        pid = fork();
        if(pid == -1)
            ERR_EXIT("fork");
        ++active_clients;
        if(pid == 0)
        {
            close(listenfd);
            sess.ctrl_fd = conn;
            if(active_clients > tunable_max_clients){
                ftp_reply(&sess,FTP_TOO_MANY_USERS,"There are too many connected users,please try later.");
                exit(EXIT_FAILURE);
            }
            signal(SIGCHLD,SIG_IGN);
            begin_session(&sess);
        }else
            close(conn);
    }

    return 0;
}

void handle_sigchld(int sig)
{
    while(waitpid(-1,NULL,WNOHANG) <= 0)
    {;}
    active_clients--;
}