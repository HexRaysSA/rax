#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc,char **argv) {
  if(argc!=5)return 2;
  int fd=open(argv[1],O_CREAT|O_EXCL|O_RDWR,0600);
  if(fd<0||ftruncate(fd,64)||lseek(fd,16,SEEK_SET)!=16)return 3;
  struct flocktimeout req={.fl={.l_start=strtoll(argv[4],NULL,10),.l_len=1,.l_type=F_WRLCK,.l_whence=(short)atoi(argv[3])},.timeout={0,0}};
  struct flocktimeout original=req;errno=0;int result=fcntl(fd,atoi(argv[2]),&req),error=errno;
  printf("{\"command\":%d,\"whence\":%d,\"start\":%lld,\"result\":%d,\"errno\":%d,\"unchanged\":%s}\n",atoi(argv[2]),atoi(argv[3]),(long long)original.fl.l_start,result,error,memcmp(&req,&original,sizeof(req))==0?"true":"false");
  return close(fd)!=0;
}
