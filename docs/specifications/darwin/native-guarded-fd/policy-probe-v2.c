#define PRIVATE 1
#include "references/guarded.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/ndr.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/fileport.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int (*open_fn)(const char *, const uint64_t *, unsigned, int, ...);
typedef int (*close_fn)(int, const uint64_t *);
typedef ssize_t (*write_fn)(int, const uint64_t *, const void *, size_t);
typedef int (*change_fn)(int, const uint64_t *, unsigned, const uint64_t *,
                         unsigned, int *);
typedef int (*kqueue_fn)(const uint64_t *, unsigned);

static void result(const char *name, long value, int error) {
  printf("{\"kind\":\"%s\",\"result\":%ld,\"errno\":%d}\n", name, value, error);
}

#pragma pack(push, 4)
struct exception_request {
  mach_msg_header_t header;
  mach_msg_body_t body;
  mach_msg_port_descriptor_t thread;
  mach_msg_port_descriptor_t task;
  NDR_record_t ndr;
  exception_type_t exception;
  mach_msg_type_number_t count;
  int64_t codes[2];
};
struct exception_reply {
  mach_msg_header_t header;
  NDR_record_t ndr;
  kern_return_t status;
};
#pragma pack(pop)

static void *receive_guard(void *argument) {
  mach_port_t port = (mach_port_t)(uintptr_t)argument;
  union {
    struct exception_request request;
    unsigned char storage[4096];
  } message = {0};
  kern_return_t status = mach_msg(&message.request.header, MACH_RCV_MSG, 0,
                                  sizeof(message), port, 0, MACH_PORT_NULL);
  if (status != KERN_SUCCESS) {
    printf("{\"kind\":\"guard-receive\",\"status\":%d}\n", status);
    return NULL;
  }
  struct exception_request *request = &message.request;
  printf("{\"kind\":\"guard-exception\",\"message_id\":%d,\"message_bytes\":%u,"
         "\"descriptors\":%u,\"exception\":%d,\"count\":%u,"
         "\"code\":\"0x%llx\",\"subcode\":\"0x%llx\"}\n",
         request->header.msgh_id, request->header.msgh_size,
         request->body.msgh_descriptor_count, request->exception,
         request->count, (unsigned long long)request->codes[0],
         (unsigned long long)request->codes[1]);
  struct exception_reply reply = {0};
  reply.header.msgh_bits =
      MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request->header.msgh_bits), 0);
  reply.header.msgh_size = sizeof(reply);
  reply.header.msgh_remote_port = request->header.msgh_remote_port;
  reply.header.msgh_id = request->header.msgh_id + 100;
  reply.ndr = NDR_record;
  reply.status = request->header.msgh_id == 2405 ? KERN_SUCCESS : MIG_BAD_ID;
  status = mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                    MACH_PORT_NULL, 0, MACH_PORT_NULL);
  printf("{\"kind\":\"guard-reply\",\"status\":%d}\n", status);
  return NULL;
}

static int install_guard_receiver(void) {
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t status =
      mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (status == KERN_SUCCESS)
    status = mach_port_insert_right(mach_task_self(), port, port,
                                    MACH_MSG_TYPE_MAKE_SEND);
  if (status == KERN_SUCCESS)
    status = task_set_exception_ports(mach_task_self(), EXC_MASK_GUARD, port,
                                      EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                      THREAD_STATE_NONE);
  printf("{\"kind\":\"guard-handler\",\"status\":%d}\n", status);
  if (status != KERN_SUCCESS)
    return 0;
  pthread_t thread;
  int error =
      pthread_create(&thread, NULL, receive_guard, (void *)(uintptr_t)port);
  if (error)
    return 0;
  pthread_detach(thread);
  return 1;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  struct rlimit core = {0, 0};
  if (setrlimit(RLIMIT_CORE, &core))
    return 2;
  if (argc == 3 && strcmp(argv[1], "inspect-fd") == 0) {
    errno = 0;
    int value = fcntl(atoi(argv[2]), F_GETFD);
    result("exec-descriptor", value, errno);
    return 0;
  }
  if (argc != 5)
    return 2;
  const char *operation = argv[1];
  unsigned attributes = (unsigned)strtoul(argv[3], NULL, 0);
  int argument = (int)strtol(argv[4], NULL, 0);
  open_fn guarded_open = (open_fn)dlsym(RTLD_DEFAULT, "guarded_open_np");
  close_fn guarded_close = (close_fn)dlsym(RTLD_DEFAULT, "guarded_close_np");
  write_fn guarded_write = (write_fn)dlsym(RTLD_DEFAULT, "guarded_write_np");
  change_fn change_guard = (change_fn)dlsym(RTLD_DEFAULT, "change_fdguard_np");
  kqueue_fn guarded_kqueue =
      (kqueue_fn)dlsym(RTLD_DEFAULT, "guarded_kqueue_np");
  if (!guarded_open || !guarded_close || !guarded_write || !change_guard ||
      !guarded_kqueue || !install_guard_receiver())
    return 3;
  uint64_t guard = UINT64_C(0x1122334455667788);
  uint64_t other = UINT64_C(0x8877665544332211);
  int plain = strncmp(operation, "plain-", 6) == 0;
  errno = 0;
  int fd = plain ? open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0600)
           : strcmp(operation, "kqueue") == 0
               ? guarded_kqueue(&guard, attributes)
               : guarded_open(argv[2], &guard, attributes,
                              O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  result("open", fd, errno);
  if (fd < 0)
    return 4;
  errno = 0;
  int value = fcntl(fd, F_GETFD);
  result("descriptor-before", value, errno);
  errno = 0;
  if (strcmp(operation, "close") == 0) {
    value = close(fd);
    result(operation, value, errno);
    fd = -1;
  } else if (strcmp(operation, "dup") == 0) {
    value = dup(fd);
    result(operation, value, errno);
    if (value >= 0)
      close(value);
  } else if (strcmp(operation, "fcntl-dup") == 0) {
    value = fcntl(fd, argument, 100);
    result(operation, value, errno);
    if (value >= 0)
      close(value);
  } else if (strcmp(operation, "dev-fd") == 0) {
    char path[64];
    snprintf(path, sizeof(path), "/dev/fd/%d", fd);
    value = open(path, O_RDWR);
    result(operation, value, errno);
    if (value >= 0)
      close(value);
  } else if (strcmp(operation, "write") == 0) {
    ssize_t count = write(fd, argument ? (void *)(uintptr_t)1 : "x", 1);
    result(operation, count, errno);
  } else if (strcmp(operation, "pwrite") == 0) {
    ssize_t count = pwrite(fd, "x", 1, 0);
    result(operation, count, errno);
  } else if (strcmp(operation, "writev") == 0) {
    struct iovec vector = {.iov_base = "x", .iov_len = 1};
    ssize_t count = writev(fd, &vector, 1);
    result(operation, count, errno);
  } else if (strcmp(operation, "setfd") == 0) {
    value = fcntl(fd, F_SETFD, argument);
    result(operation, value, errno);
  } else if (strcmp(operation, "close-wrong") == 0 ||
             strcmp(operation, "plain-guarded-close") == 0) {
    value = guarded_close(fd, &other);
    result(operation, value, errno);
  } else if (strcmp(operation, "write-wrong") == 0 ||
             strcmp(operation, "plain-guarded-write") == 0) {
    ssize_t count = guarded_write(fd, &other, "x", 1);
    result(operation, count, errno);
  } else if (strcmp(operation, "change-remove") == 0 ||
             strcmp(operation, "change-wrong") == 0 ||
             strcmp(operation, "change-replace") == 0 ||
             strcmp(operation, "plain-change-add") == 0) {
    int flags = argument;
    const uint64_t *old = plain                                    ? NULL
                          : strcmp(operation, "change-wrong") == 0 ? &other
                                                                   : &guard;
    const uint64_t *replacement = strcmp(operation, "change-remove") == 0 ||
                                          strcmp(operation, "change-wrong") == 0
                                      ? NULL
                                      : &other;
    value = change_guard(fd, old, plain ? 0 : attributes, replacement,
                         replacement ? 2 : 0, &flags);
    result(operation, value, errno);
    result("change-old-flags", flags, 0);
    if (value == 0) {
      if (replacement)
        guard = other;
      else
        plain = 1;
    }
  } else if (strcmp(operation, "fork") == 0 ||
             strcmp(operation, "fork-after-clear") == 0 ||
             strcmp(operation, "exec-after-clear") == 0) {
    if (strcmp(operation, "fork") != 0) {
      value = fcntl(fd, F_SETFD, FD_CLOEXEC);
      result("clear-clofork", value, errno);
      if (value != 0)
        return 5;
    }
    pid_t child = fork();
    if (child == 0) {
      if (strcmp(operation, "exec-after-clear") == 0) {
        char number[32];
        snprintf(number, sizeof(number), "%d", fd);
        execl(argv[0], argv[0], "inspect-fd", number, NULL);
        _exit(6);
      }
      errno = 0;
      value = fcntl(fd, F_GETFD);
      result("child-descriptor", value, errno);
      _exit(0);
    }
    if (child < 0)
      return 7;
    int status;
    if (waitpid(child, &status, 0) != child)
      return 8;
    result("child-wait-status", status, 0);
  } else if (strcmp(operation, "fileport") == 0) {
    fileport_t port = MACH_PORT_NULL;
    value = fileport_makeport(fd, &port);
    result(operation, value, errno);
    if (value == KERN_SUCCESS)
      mach_port_deallocate(mach_task_self(), port);
  } else if (strcmp(operation, "socket-transfer") == 0) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair))
      return 9;
    char bytes[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec vector = {.iov_base = "x", .iov_len = 1};
    struct msghdr message = {.msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = bytes,
                             .msg_controllen = sizeof(bytes)};
    struct cmsghdr *control = CMSG_FIRSTHDR(&message);
    control->cmsg_len = CMSG_LEN(sizeof(int));
    control->cmsg_level = SOL_SOCKET;
    control->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(control), &fd, sizeof(fd));
    ssize_t sent = sendmsg(pair[0], &message, 0);
    result(operation, sent, errno);
    close(pair[0]);
    close(pair[1]);
  } else if (strcmp(operation, "kqueue") != 0) {
    return 10;
  }
  if (fd >= 0) {
    errno = 0;
    value = fcntl(fd, F_GETFD);
    result("descriptor-after", value, errno);
    errno = 0;
    value = plain ? close(fd) : guarded_close(fd, &guard);
    result("cleanup", value, errno);
  }
  return 0;
}
