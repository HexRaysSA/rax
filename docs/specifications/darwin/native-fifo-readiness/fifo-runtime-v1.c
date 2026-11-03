#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

struct operation { int fd, vector; atomic_int started; ssize_t count; int error; char byte; };
static ssize_t transfer(int fd, char *buf, size_t length, int vector) {
  struct iovec item = {.iov_base=buf,.iov_len=length};
  return vector ? readv(fd,&item,1) : read(fd,buf,length);
}
static void record(const char *name, long value) { printf("%s=%ld\n",name,value); }
static void *reading(void *raw) {
  struct operation *op=raw;
  atomic_store(&op->started,1);errno=0;
  op->count=transfer(op->fd,&op->byte,1,op->vector);op->error=errno;return NULL;
}
int main(int argc,char **argv) {
  if(argc!=3) return 2;
  setvbuf(stdout,NULL,_IONBF,0);
  int vector=atoi(argv[1]);
  if(mkfifo(argv[2],0600)) return 3;
  int rd=open(argv[2],O_RDONLY|O_NONBLOCK);
  if(rd<0||fcntl(rd,F_SETFL,0)) return 4;
  char byte='?';
  for(int i=0;i<3;++i) { ssize_t n=transfer(rd,&byte,1,vector);record("never-writer-eof",n);if(n) return 5; }
  int wr=open(argv[2],O_WRONLY|O_NONBLOCK);
  if(wr<0||unlink(argv[2])) return 6;
  ssize_t zero=transfer(rd,&byte,0,vector);record("empty-zero-read",zero);if(zero) return 7;
  struct operation op={.fd=rd,.vector=vector,.byte='?'};pthread_t thread;
  if(pthread_create(&thread,NULL,reading,&op)) return 8;
  int blocked=0;
  for(int i=0;i<5000;++i) {
    thread_basic_info_data_t info;mach_msg_type_number_t count=THREAD_BASIC_INFO_COUNT;
    if(atomic_load(&op.started)&&thread_info(pthread_mach_thread_np(thread),THREAD_BASIC_INFO,(thread_info_t)&info,&count)==KERN_SUCCESS&&info.run_state==TH_STATE_WAITING) { blocked=1;break; }
    usleep(1000);
  }
  record("reader-blocked",blocked);if(!blocked) return 9;
  pid_t child=fork();if(child<0) return 10;
  if(child==0) { int result=fcntl(rd,F_SETFL,O_NONBLOCK);_exit(result?11:0); }
  int status=-1;if(waitpid(child,&status,0)!=child||status) return 12;
  record("child-exit",status);
  if(write(wr,"x",1)!=1||pthread_join(thread,NULL)) return 13;
  record("read-result",op.count);record("read-errno",op.error);record("read-byte",op.byte);
  record("shared-nonblock",!!(fcntl(rd,F_GETFL)&O_NONBLOCK));
  if(op.count!=1||op.byte!='x') return 14;
  if(fcntl(rd,F_SETFL,0)||close(wr)) return 15;
  for(int i=0;i<3;++i) { ssize_t n=transfer(rd,&byte,1,vector);record("after-writer-eof",n);if(n) return 16; }
  return close(rd)?17:0;
}
