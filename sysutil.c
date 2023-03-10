#include "sysutil.h"

/**
 * tcp_server - start a tcp server
 * @host:   host name or server ip address
 * @port:   server port
 * @return: return listenfd or return -1 signed err
*/

int tcp_client(unsigned short port)
{
    int sock;
    if((sock = socket(PF_INET,SOCK_STREAM,0)) < 0)
        ERR_EXIT("tcp_client");
    if(port > 0)
    {
        int on = 1;
        if((setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(const char *)&on,sizeof(on))) < 0)
            ERR_EXIT("setsockopt");
        struct sockaddr_in localaddr;
        char ip[16] = {0};
        getlocalip(ip);
        memset(&localaddr,0,sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_port = htons(port);
        localaddr.sin_addr.s_addr = inet_addr(ip);
        if(bind(sock,(struct sockaddr *)&localaddr,sizeof(localaddr)) < 0)
            ERR_EXIT("bind is error");
    }
    return sock;
}
int tcp_server(const char *host,unsigned short port){
    int listenfd;
    if((listenfd = socket(PF_INET,SOCK_STREAM,0)) < 0)
        ERR_EXIT("socket");
    struct sockaddr_in servaddr;
    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if(host != NULL)
    {
        if((inet_aton(host,&servaddr.sin_addr)) == 0)
        {
            struct hostent *hp;
            hp = gethostbyname(host);
            if(hp == NULL)
                ERR_EXIT("gethostbyname");
            servaddr.sin_addr.s_addr = *(in_addr_t*)hp->h_addr;
        }
    }else
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    servaddr.sin_port = htons(port);

    int on = 1;
    if(setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,(const char *)&on,sizeof(on)) < 0)
        ERR_EXIT("setsockopt");
    if(bind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr)) < 0)
        ERR_EXIT("bind");
    if(listen(listenfd,SOMAXCONN) < 0)
        ERR_EXIT("listen");
    
    return listenfd;
}

int getlocalip(char *ip){
    char host[100] = {0}; 
    if(gethostname(host,sizeof(host)) < 0)
        return -1;
    struct hostent *hp;
    if((hp = gethostbyname(host)) == NULL)
        return -1;
    strcpy(ip,inet_ntoa(*(struct in_addr*)hp->h_addr));
    return 0;
}

void activate_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd,F_GETFL);
    if(flags == -1)
        ERR_EXIT("fcntl");
    
    flags |= O_NONBLOCK;
    ret = fcntl(fd,F_SETFL,flags);
    if(ret == -1)
        ERR_EXIT("fcntl");
}

void deactivate_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd,F_GETFL);
    if(flags == -1)
        ERR_EXIT("fcntl");
    
    flags &= ~O_NONBLOCK;
    ret = fcntl(fd,F_SETFL,flags);
    if(ret == -1)
        ERR_EXIT("fcntl");
}
/**
 * read_timeout:read timeout test
 * @fd:file dis
 * @wait_seconds:timeout
 * @return:success 0 ,fail -1 ,timeout -1 and errno = ETIMEOUT;
*/
int read_timeout(int fd,unsigned int wait_seconds){
    int ret = 0;
    if(wait_seconds > 0)
    {
        fd_set read_fdset;
        struct timeval timeout;

        FD_ZERO(&read_fdset);
        FD_SET(fd,&read_fdset);

        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd+1,&read_fdset,NULL,NULL,&timeout);
        } while (ret < 0 && errno == EINTR);
        
        if(ret == 0)
        {
            ret = -1;
            errno = ETIMEDOUT;
        }else if(ret == 1)
            ret = 0;
    }
    return ret;
}
int write_timeout(int fd,unsigned int wait_seconds)
{
    int ret = 0;
    if(wait_seconds > 0)
    {
        fd_set write_fdset;
        struct timeval timeout;

        FD_ZERO(&write_fdset);
        FD_SET(fd,&write_fdset);

        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd+1,NULL,NULL,&write_fdset,&timeout);
        } while (ret < 0 && errno == EINTR);
        
        if(ret == 0)
        {
            ret = -1;
            errno = ETIMEDOUT;
        }else if(ret == 1)
            ret = 0;
    }
    return ret;
}

int accept_timeout(int fd,struct sockaddr_in *addr,unsigned int wait_seconds)
{
    int ret;
    socklen_t addrlen = sizeof(struct sockaddr_in);
    if(wait_seconds > 0)
    {
        fd_set accept_fdset;
        struct timeval timeout;
        FD_ZERO(&accept_fdset);
        FD_SET(fd,&accept_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd+1,&accept_fdset,NULL,NULL,&timeout);
        }while(ret < 0 && errno == EINTR);
        if(ret == -1)
            return -1;
        else if(ret == 0)
        {
            errno = ETIMEDOUT;
            return -1;
        }
    }
    if(addr != NULL)
        ret = accept(fd,(struct sockaddr *)addr,&addrlen);
    else
        ret = accept(fd,NULL,NULL);
    
    return ret;
}

int connect_timeout(int fd,struct sockaddr_in *addr,unsigned int wait_seconds)
{
    int ret;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    if(wait_seconds > 0)
        activate_nonblock(fd);
    ret = connect(fd,(struct sockaddr *)addr,addrlen);
    if(ret < 0 && errno == EINPROGRESS)
    {
        fd_set connect_fdset;
        struct timeval timeout;
        FD_ZERO(&connect_fdset);
        FD_SET(fd,&connect_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do{
            ret = select(fd + 1,NULL,&connect_fdset,NULL,&timeout);
        }while(ret < 0 && errno == EINTR);
        if(ret == 0)
        {
            ret = -1;
            errno = ETIMEDOUT;
        }else if(ret < 0)
            return -1;
        else if(ret == 1)
        {
            int err;
            socklen_t socklen = sizeof(err);
            int sockoptret = getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&socklen);
            if(sockoptret == -1)
            {
                return -1;
            }
            if(err == 0)
            {
                ret = 0;
            }else
            {
                errno = err;
                ret = -1;
            }
        }
    }
    if(wait_seconds > 0)
        deactivate_nonblock(fd);
    return ret;
}

ssize_t readn(int fd,void *buf,size_t count)
{
    ssize_t nleft = count;
    ssize_t nread;
    char *bufp = (char *)buf;

    while(nleft > 0)
    {
        if((nread = read(fd,bufp,nleft)) < 0)
        {
            if(errno == EINTR)
                continue;
            return -1;
        }else if(nread == 0)
            return count - nleft;
        bufp += nread;
        nleft -= nread;
    }
    return count;
}
ssize_t writen(int fd,const void *buf,size_t count)
{
    ssize_t nleft = count;
    ssize_t nwriten;
    char *bufp = (char *)buf;

    while(nleft > 0)
    {
        if((nwriten = write(fd,bufp,nleft)) < 0)
        {
            if(errno == EINTR)
                continue;
            return -1;
        }else if(nwriten == 0)
            continue;

        bufp += nwriten;
        nleft -= nwriten;
    }
    return count;
}
ssize_t recv_peek(int sockfd,void *buf,size_t len)
{
    while(1)
    {
        int ret = recv(sockfd,buf,len,MSG_PEEK);
        if(ret == -1 && errno == EINTR)
            continue;
        return ret;
    }
}
ssize_t readline(int sockfd,void *buf,size_t maxline)
{
    int ret;
    int nread;
    char *bufp = buf;
    int nleft = maxline;
    while(1)
    {
        ret = recv_peek(sockfd,bufp,nleft);
        if(ret < 0)
            return ret;
        else if(ret == 0)
            return ret;
        nread = ret;
        int i;
        for(i = 0;i < nread;++i)
        {
            if(bufp[i] == '\n')
            {
                ret = readn(sockfd,bufp,i+1);
                if(ret != i + 1)
                    exit(EXIT_FAILURE);
                return ret;
            }
        }
        if(nread > nleft)
            exit(EXIT_FAILURE);
        nleft -= nread;
        ret = read(sockfd,bufp,nread);
        if(ret != nread)
            exit(EXIT_FAILURE);
        
        bufp += nread;
    }
    return -1;
}

void send_fd(int sock_fd,int fd)
{
    int ret;
    struct msghdr msg;
    struct cmsghdr *p_cmsg;
    struct iovec vec;
    char cmsgbuf[CMSG_SPACE(sizeof(fd))];
    int *p_fds;
    char sendchar = 0;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    p_cmsg = CMSG_FIRSTHDR(&msg);
    p_cmsg->cmsg_level = SOL_SOCKET;
    p_cmsg->cmsg_type = SCM_RIGHTS;
    p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    p_fds = (int *)CMSG_DATA(p_cmsg);
    *p_fds = fd;

    vec.iov_base = &send_fd;
    vec.iov_len = sizeof(sendchar);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;

    
    ret = sendmsg(sock_fd,&msg,0);
    if(ret != 1)
        ERR_EXIT("sendmsg");

}
int recv_fd(const int sock_fd)
{
    int ret;
    struct msghdr msg;
    char recvchar;
    struct iovec vec;
    int recv_fd;
    char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
    struct cmsghdr *p_cmsg;
    int *p_fd;

    vec.iov_base = &recvchar;
    vec.iov_len = sizeof(recvchar);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    msg.msg_flags = 0;

    p_fd = (int *)CMSG_DATA(CMSG_FIRSTHDR(&msg));
    *p_fd = -1;
    ret = recvmsg(sock_fd,&msg,0);
    if(ret != 1)
        ERR_EXIT("recvmsg");
    p_cmsg = CMSG_FIRSTHDR(&msg);
    if(p_cmsg == NULL)
        ERR_EXIT("no passed fd");
    
    p_fd = (int *)CMSG_DATA(p_cmsg);
    recv_fd = *p_fd;
    if(recv_fd == -1)
        ERR_EXIT("no pass fd");
        
    return recv_fd;
}
const char *statbuf_get_perms(struct stat *sbuf)
{
    static char perms[] = "----------";
    for(int i = 1;i < 10;++i)
    {
        perms[i] = '-';
    }
    perms[0] = '?';
    mode_t mode = sbuf->st_mode;
    switch(mode & S_IFMT)
    {
    case S_IFREG:
        perms[0] = '-';
        break;
    case S_IFDIR:
        perms[0] = 'd';
        break;
    case S_IFLNK:
        perms[0] = 'l';
        break;
    case S_IFIFO:
        perms[0] = 'p';
        break;
    case S_IFSOCK:
        perms[0] = 's';
        break;
    case S_IFCHR:
        perms[0] = 'c';
        break;
    case S_IFBLK:
        perms[0] = 'b';
        break;
    }

    if(mode & S_IRUSR)
        perms[1] = 'r';
    if(mode & S_IWUSR)
        perms[2] = 'w';
    if(mode & S_IXUSR)
        perms[3] = 'x';

    if(mode & S_IRGRP)
        perms[4] = 'r';
    if(mode & S_IWGRP)
        perms[5] = 'w';
    if(mode & S_IXGRP)
        perms[6] = 'x';

    if(mode & S_IROTH)
        perms[7] = 'r';
    if(mode & S_IWOTH)
        perms[8] = 'w';
    if(mode & S_IXOTH)
        perms[9] = 'x';
    if(mode & S_ISUID)
        perms[3] = (perms[3] == 'x')?'s':'S';
    if(mode & S_ISGID)
        perms[6] = (perms[6] == 'x')?'s':'S';
    if(mode & S_ISVTX)
        perms[9] = (perms[9] == 'x')?'t':'T';
    return perms;
}

const char *statbuf_get_date(struct stat *sbuf)
{
    static char datebuf[64] = {0};
    memset(datebuf,0,sizeof(datebuf));
    const char *p_data_format = "%b %e %H:%M";
    struct timeval tv;
    gettimeofday(&tv,NULL);
    long local_time = tv.tv_sec;
    if(sbuf->st_mtim.tv_sec > local_time || (local_time - sbuf->st_mtim.tv_sec) > 60*60*24*182)
    {
        p_data_format = "%b %e %Y";
    }
    
    struct tm *p_tm = localtime(&local_time);
    strftime(datebuf,sizeof(datebuf),p_data_format,p_tm);
    return datebuf;
}

static int lock_internal(int fd,short int lock_type)
{
    int ret;
    struct flock the_lock;
    memset(&the_lock,0,sizeof(the_lock));
    the_lock.l_type = lock_type;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;
    do{
        ret = fcntl(fd,F_SETLKW,&the_lock);
    }while(ret < 0 && errno == EINTR);

    return ret;
}
int lock_file_read(int fd)
{
    return lock_internal(fd,F_RDLCK);
}

int lock_file_write(int fd)
{
    return lock_internal(fd,F_WRLCK);
}

int unlock_file(int fd)
{
    int ret;
    struct flock the_lock;
    memset(&the_lock,0,sizeof(the_lock));
    the_lock.l_type = F_UNLCK;
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0;
    ret = fcntl(fd,F_SETLK,&the_lock);

    return ret;
}

void limit_rate(struct timeval *beg_time,int transfered_bytes,unsigned int max_rate)
{
    int ret;
    struct timeval curr_time;
    if(gettimeofday(&curr_time,NULL) < 0)
        ERR_EXIT("gettimeofday");
    double elapsed;
    elapsed = (double)(curr_time.tv_sec - beg_time->tv_sec);
    elapsed += (double)(curr_time.tv_usec - beg_time->tv_usec)/(double)1000000;
    if(elapsed <= 0)
        elapsed = 0.01;
    unsigned int bw_rate = (unsigned int)((double)transfered_bytes / elapsed);
    if(bw_rate <= max_rate)
        return;
    double rate_ratio = bw_rate/max_rate;
    double pause_time = (rate_ratio - (double)1)*elapsed;
    struct timespec sleep_time;
    sleep_time.tv_sec = pause_time;
    sleep_time.tv_nsec = (pause_time - sleep_time.tv_sec)*1000000000;
    do{
        ret = nanosleep(&sleep_time,&sleep_time);
    }while(ret == -1 && errno == EINTR);

}

void activate_oobinline(int fd)
{
    int oob_inline = 1;
    int ret;
    ret = setsockopt(fd,SOL_SOCKET,SO_OOBINLINE,&oob_inline,sizeof(oob_inline));
    if(ret == -1)
        ERR_EXIT("setsockopt");
}

void activate_sigurg(int fd)
{
    int ret;
    ret = fcntl(fd,F_SETOWN,getpid());
    if(ret == -1)
    {
        ERR_EXIT("fcntl");
    }
}
