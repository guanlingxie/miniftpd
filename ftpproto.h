#ifndef FTPPROTO_H__
#define FTPPROTO_H__

#include "session.h"

void handle_child(session_t *sess);
int list_common(session_t *sess,int detail);
void ftp_reply(session_t *sess,int status,const char *text);

#endif