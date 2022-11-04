
#include "str.h"
#include "common.h"

void str_trim_crlf(char *str)
{
    char *p = &(str[strlen(str) - 1]);
    while(*p == '\r' || *p == '\n')
        *p-- = '\0';
}

void str_split(const char *str,char *left,char *right,char c)
{
    char *p = strchr(str,c);
    if(p == NULL && left)
        strcpy(left,str);
    else{
        strncpy(left,str,p-str);
        strcpy(right,p+1);
    }
}

int str_all_space(const char *str)
{
    while(*str)
    {
        if(!isspace(*str))
            return 0;
        str++;
    }
    return 1;
}
void str_upper(char *str)
{
    while(*str)
    {
        *str = toupper(*str);
        str++;
    }
}
long long str_to_longlong(const char *str)
{
    long long res = 0;
    const char *p = str;
    //res = atoll(str);
    while(*p >= '0' && *p <= '9')
    {
        res *= 10;
        res += *p - '0';
        ++p;
    }
    return res;
}
unsigned int str_octal_to_uint(const char *str)
{
    unsigned int res = 0;
    const char *p = str;
    //res = atoll(str);
    while(*p >= '0' && *p <= '7')
    {
        res *= 8;
        res += *p - '0';
        ++p;
    }
    return res;
}