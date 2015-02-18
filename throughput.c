// -*-  mode: c; eval: (orgstruct++-mode); eval: (setq orgstruct-heading-prefix-regexp "// ");  -*-

//#define SCTP_DEBUG
//#define INVARIANTS
#define __Userspace__
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <usrsctp.h>
// * Prototypes
void fail(struct socket * assoc, int sid, const char *message, ...);

// * Closure Queue

typedef void (*op_fn)(void* context);

TAILQ_HEAD(op_closure_head, op_closure) op_q_head;

struct op_closure {
  TAILQ_ENTRY(op_closure) entries;
  op_fn opc_fun;
  void* opc_context;
};

pthread_cond_t op_queue_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t op_queue_lock = PTHREAD_MUTEX_INITIALIZER;
enum QueueState { qsOPEN, qsCLOSING } op_queue_state;

unsigned long delay_ms(struct timespec* from, struct timespec *to) {
  unsigned long sec = to->tv_sec - from->tv_sec;
  long nsec = to->tv_nsec - from->tv_nsec;
  if (nsec < 0) {
    sec -= 1;
    nsec += 1000000000;
  }
  return (sec * 1000) + (nsec / 1000000);
}

struct op_closure* get_next_op() {
  struct op_closure* closure = NULL;
  enum QueueState state;
  struct timespec wait, start, now;
  /* repeatedly try to get something from the queue until we get something or
     the queue goes into qsCLOSING. */
  do {
    /* only bother with the condition if we find that the queue's empty */
    pthread_mutex_lock(&op_queue_lock);
    if (op_q_head.tqh_first == NULL) {
      pthread_mutex_unlock(&op_queue_lock);
      printf("get_next_op: pthread_cond_timedwait\n");
      clock_gettime(CLOCK_REALTIME, &start);
      do {
        clock_gettime(CLOCK_REALTIME, &wait);
        wait.tv_sec += 2;  // wait 2 sec.
      } while (pthread_cond_timedwait(&op_queue_cond, &op_queue_lock, &wait) == EAGAIN);
      clock_gettime(CLOCK_REALTIME, &now);
      printf("get_next_op: took %lu ms in wait.\n", delay_ms(&start, &now));
    }
    printf("get_next_op: looking at queue\n");
    if ((state = op_queue_state) == qsOPEN) {
      if ((closure = op_q_head.tqh_first) != NULL) {
        printf("get_next_op: got entry %p\n", closure);
        TAILQ_REMOVE(&op_q_head, closure, entries);
      }
    }
    printf("get_next_op: unlocking queue.\n");
    pthread_mutex_unlock(&op_queue_lock);
  } while (closure == NULL && state == qsOPEN);
  return closure;
}

void queue_op(op_fn fn, void *context) {
  struct op_closure *op = (struct op_closure*) malloc(sizeof (struct op_closure));
  op->opc_fun = fn;
  op->opc_context = context;
  pthread_mutex_lock(&op_queue_lock);
  TAILQ_INSERT_TAIL(&op_q_head, op, entries);
  printf("queue_op: Signalling\n");
  pthread_cond_signal(&op_queue_cond);
  pthread_mutex_unlock(&op_queue_lock);
}

static void * run_closure_queue (void* unused) {
  struct op_closure* op;
  do {
    // Can block getting another item from the queue, and will kill the
    // thread when the queue's dying, by returning NULL.
    printf("RUN_CLOSURE_QUEUE: waiting\n");
    op = get_next_op();
    printf("RUN_CLOSURE_QUEUE: Got %p\n", op);
    usleep(100);
    if (op == NULL) {
      return NULL;
    } else if (!op->opc_fun) {
      fprintf(stderr, "Bad closure, no function @ %p\n", op);
    } else {
      op->opc_fun(op->opc_context);
    }
    free(op);
  } while (1);
}

// * Low-level I/O

int assoc_id(struct socket* assoc) {
  return ((intptr_t) assoc) & 0x7f0 >> 7;
}

struct fd_info {
  TAILQ_ENTRY(fd_info) entries;
  int port;
  // actually an (opaque) pointer to run_single_test's udp_fd.  We don't
  // dereference it.
  intptr_t udp_fd, peer_fd;
  struct sockaddr_in peer_addr;
};

pthread_mutex_t client_list_lock = PTHREAD_MUTEX_INITIALIZER;
TAILQ_HEAD(fd_info_head, fd_info) all_clients;

struct data_desc {
  int assoc;
  int sid;
};

void
debug_printf(const char *format, ...)
{
  va_list ap;

  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
  fflush(stdout);
}

#define CHECK(x)  do { if (!(x)) {                                  \
      printf("FAILURE (%s:%d): " #x " was false, aborting: %s\n",   \
             __FILE__, __LINE__, strerror(errno));                  \
      exit(1); } } while (0)

// some examples use this, some don't.
static int
conn_output(void *addr, void *buf, size_t length, uint8_t tos, uint8_t set_df)
{
  char *dump_buf;
  int fdp;
  struct fd_info *inf;
  struct sockaddr_in peer;
  char ipbuf[64];

  printf("[Output %ld bytes: addr=%p buf=%p tos=%x set_df=%x]\n",
         length, addr, buf, tos, set_df);
  fflush(stdout);

  fdp = (intptr_t)addr;
  pthread_mutex_lock(&client_list_lock);
  for (inf = all_clients.tqh_first; inf != NULL; inf = inf->entries.tqe_next) {
    if (fdp == inf->udp_fd) {
      peer = inf->peer_addr;
      break;
    }
  }
  pthread_mutex_unlock(&client_list_lock);

  if (inf == NULL) {
    printf("[OUTPUT FAILURE: peer for fd %d not found]\n", fdp);
    return EBADF;
  }

#ifdef SCTP_DEBUG
  if ((dump_buf = usrsctp_dumppacket(buf, length,
                                     SCTP_DUMP_OUTBOUND)) != NULL) {
    fprintf(stderr, "%s", dump_buf);
    usrsctp_freedumpbuffer(dump_buf);
  }

  printf("(W): send(%d): %ld bytes to %s:%d\n", fdp, length,
         inet_ntop(AF_INET, &peer.sin_addr, ipbuf, 64),
         htons(peer.sin_port));
#endif /* SCTP_DEBUG */
  if (sendto(fdp, buf, length, 0,
             (struct sockaddr*) &peer, sizeof(struct sockaddr_in)) < 0) {
    perror("send");
    return (errno);
  } else {
    return (0);
  }
}

#define MAX_PACKET_SIZE (65536)


static void *
handle_packets(void *arg)
{
  fd_set fdset;
  int fd, max_fd, i;

  ssize_t io_length;
  char io_buf[MAX_PACKET_SIZE];
  char *io_bufp;
  struct fd_info *inf;
  struct fd_info *fds;
  int num_fds, max_fds;
  max_fds = 16;
  fds = (struct fd_info*) malloc(sizeof(struct fd_info) * max_fds);

  while (1) {
    int nr = 0;

    struct timeval tmout;
    tmout.tv_sec = 1;
    tmout.tv_usec = 0;

    FD_ZERO(&fdset);
    max_fd = -1;

    io_bufp = io_buf +
      snprintf(io_buf, MAX_PACKET_SIZE, "(IO): select(2) on UDP fds ");

    pthread_mutex_lock(&client_list_lock);
    for (inf = all_clients.tqh_first; inf != NULL; inf = inf->entries.tqe_next) {
      int fd = inf->udp_fd;
#ifdef SCTP_DEBUG
      io_bufp += snprintf(io_bufp, MAX_PACKET_SIZE - (io_bufp - io_buf),
                          (inf != all_clients.tqh_first? ", %d" : "%d"), fd);
#endif /* SCTP_DEBUG */
      max_fd = max_fd > fd? max_fd : fd;
      FD_SET(fd, &fdset);
      nr++;
    }
    pthread_mutex_unlock(&client_list_lock);

    if (max_fd > max_fds) {
      while (max_fds < max_fd) {
        max_fds *= 2;
      }
      fds = (struct fd_info*) realloc(fds, sizeof(struct fd_info) * max_fds);
    }

    if (max_fd < 1) {
      printf("(IO): no FDs to read. sleeping.\n");
      sleep(1);
      continue;
    }

#ifdef SCTP_DEBUG
    puts(io_buf);
#endif /* SCTP_DEBUG */

    nr = select(max_fd + 1, &fdset, NULL, NULL, &tmout);
    if (nr < 0) {
      perror("select");
      sleep(1);
    }

    if (nr) {
      num_fds = 0;
      /* copy any fd_infos that need reading into our own buffer, so
         that we don't hold the lock while calling into usrsctp
         again.*/
      pthread_mutex_lock(&client_list_lock);
      for (inf = all_clients.tqh_first; inf != NULL; inf = inf->entries.tqe_next) {
        fd = inf->udp_fd;
        if (FD_ISSET(fd, &fdset)) {
          fds[num_fds++] = *inf;
        }
      }
      pthread_mutex_unlock(&client_list_lock);


      for (i = 0; i < num_fds; i++) {
        struct sockaddr_in sock_addr;
        socklen_t sz;
        char ipbuf[32], ipbuf2[32];
        sz = sizeof(struct sockaddr_in);
        io_length = recvfrom(fds[i].udp_fd, io_buf, MAX_PACKET_SIZE, 0,
                             (struct sockaddr*) &sock_addr, &sz);
#ifdef SCTP_DEBUG
        printf("(IO): %ld input on fd %d\n  IP: %s:%d\n  Peer IP: %s:%d\n",
               io_length, fd,
               inet_ntop(AF_INET, &sock_addr.sin_addr, ipbuf, 32),
               ntohs(sock_addr.sin_port),
               inet_ntop(AF_INET, &fds[i].peer_addr.sin_addr, ipbuf2, 32),
               ntohs(fds[i].peer_addr.sin_port));
#endif /* SCTP_DEBUG */
        if (io_length > 0) {
          usrsctp_conninput((void*) fds[i].udp_fd,
                            io_buf, (size_t)io_length, 0);
        } else {
          perror("recv");
        }
      }
    }
  }
  return (NULL);
}

// * High-level I/O
/* When sock_refcnt goes to zero, close the socket */
struct op_shared_sock {
  pthread_mutex_t mutex;
  int sock_refcnt;
  struct socket* assoc;
};

struct op_send_ctx {
  struct op_shared_sock *sock;
  int sid;
  int len;
};

struct op_shared_sock* wrap_socket(struct socket* assoc) {
  struct op_shared_sock *ret = (struct op_shared_sock*) malloc(
    sizeof (struct op_shared_sock));
  ret->assoc = assoc;
  ret->sock_refcnt = 0;
  pthread_mutex_init(&ret->mutex, NULL);
  return ret;
}

void op_sock_addref(struct op_shared_sock *sock) {
  pthread_mutex_lock(&sock->mutex);
  sock->sock_refcnt++;
  pthread_mutex_unlock(&sock->mutex);
}

struct socket* op_sock_delref(struct op_shared_sock *sock) {
  struct socket *assoc;
  pthread_mutex_lock(&sock->mutex);
  if (--sock->sock_refcnt == 0) {
    pthread_mutex_unlock(&sock->mutex);
    usrsctp_close(sock->assoc);
    pthread_mutex_destroy(&sock->mutex);
    free(sock);
    return NULL;
  } else {
    assoc = sock->assoc;
    pthread_mutex_unlock(&sock->mutex);
    return assoc;
  }
}

void op_send_some_data(void *opdata) {
  /* we can delref before sending, because there's still a ref for when we
     receive the data */
  struct op_send_ctx *ctx = (struct op_send_ctx*) opdata;
  struct socket* assoc = op_sock_delref(ctx->sock);
  int sid = ctx->sid;
  int len = ctx->len;
  int ret;
  uint8_t *buffer = (uint8_t*) malloc(len);
  uint8_t *buf_end = buffer + len;
  uint32_t key = assoc_id(assoc) ^ sid;
  uint32_t *bufkey = (uint32_t*) buffer;
  uint32_t *bufkey_end = bufkey + (len / 4);
  uint8_t *buf_last = buffer + len - (len % 4);
  struct sctp_sndinfo sndinfo;
  int i;
  
  for (i = 0; i < len / 4; i++) {
    bufkey[i] = key;
  }
  
  for (i = 0; i < len % 4; i++) {
    buf_last[i] = (uint8_t) i;
  }
  
  if (len >= sizeof(struct data_desc)) {
    struct data_desc tag;
    tag.assoc = assoc_id(assoc);
    tag.sid = sid;
    memcpy(buffer, &tag, sizeof(struct data_desc));
  }
  
  bzero(&sndinfo, sizeof(struct sctp_sndinfo));
  sndinfo.snd_sid = sid;
  sndinfo.snd_context = htonl(key);
  
  ret = usrsctp_sendv(assoc, buffer, len, NULL, 0, &sndinfo,
                      sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0);
  free(buffer);

  if (ret < 0 && errno == EAGAIN) {
    // OK, queue it again.
    op_sock_addref(ctx->sock);
    queue_op(&op_send_some_data, (void*) ctx);
  } else if (ret != len) {
    printf("op_send_some_data(0x.., %d, %d): failed, ret=%d, errno=%d\n", sid, len, ret, errno);
    perror("usrsctp_sendv");
    CHECK(ret == len);
  } else {
    free(ctx);
  }
}

void send_some_data(struct op_shared_sock* sock, int sid, int len) {
  struct op_send_ctx *ctx = (struct op_send_ctx*) malloc(sizeof (struct op_send_ctx));
  // Once for the pending write, and one for the reception of the data on the other side.
  op_sock_addref(sock);
  op_sock_addref(sock);
  ctx->sock = sock;
  ctx->sid = sid;
  ctx->len = len;
  queue_op(&op_send_some_data, (void*) ctx);
}

/* cond_counter is used to notify chagnes on sid_counts */
pthread_cond_t cond_counter = PTHREAD_COND_INITIALIZER;
/*
 * cond_lock protects:
 * - sid_counts
 * - sid_usage
 * - max_sid_usage
*/

#define MAX_SEND_SIZE (16384)
int s_send_size = MAX_SEND_SIZE;
#define SEND_SIZE (s_send_size)
pthread_mutex_t cond_lock = PTHREAD_MUTEX_INITIALIZER;
#define NUM_SIDS (s_num_sids)
#define MAX_NUM_SIDS (1024)
int s_num_sids = MAX_NUM_SIDS;
/* Counts, per stream id, of received messages */
static int sid_counts[MAX_NUM_SIDS];
/* Counts, per stream id, of sent messages */
static int sid_usage[MAX_NUM_SIDS];
static int max_sid_usage;

int choose_unused_sid() {
  int sids_tried = 0;
  int found_sid = -1;
  int sid = rand() % NUM_SIDS;
  int counts[MAX_NUM_SIDS];
  int i, max;
#define LINEBUFSZ (16384)
  char linebuf[LINEBUFSZ];
  char *appendp;
  pthread_mutex_lock(&cond_lock);
  max = max_sid_usage;
  for (i = 0; i < NUM_SIDS; i++) {
    counts[i] = sid_usage[i];
  }
  while (sids_tried < NUM_SIDS && found_sid < 0) {
    if (sid_usage[sid] < max_sid_usage) {
      found_sid = sid;
    } else {
      sid = (1+sid) % NUM_SIDS;
    }
    sids_tried++;
  }
  if (found_sid < 0) {
    // all SIDs are at max_sid_usage.
    found_sid = sid;
    max_sid_usage = sid_usage[sid] + 1;
    printf("** max_sid_usage is now %d **\n", max_sid_usage);
  }
  sid_usage[found_sid]++;

  pthread_mutex_unlock(&cond_lock);
  /*  printf("choose_unused_sid: returning %d\n", found_sid);
  printf("choose_unused_sid:  pre-acquire state: max_sid_usage = %d\n", max_sid_usage);
  appendp = linebuf + snprintf(linebuf, LINEBUFSZ, "choose_unused_sid:");
  for (i = 0 ; i < NUM_SIDS; i++) {
    appendp += snprintf(appendp, LINEBUFSZ - (appendp - linebuf), " %d", counts[i]);
  }
  puts(linebuf); */
  return sid;
}

/* Assume same endian-ness on both machines.  Otherwise, fix this. */
int verify_data(struct socket *assoc,
                union sctp_sockstore addr,
                void *buffer,
                size_t len,
                struct sctp_rcvinfo info,
                int flags,
                void *wtf_is_this) {
  int sid = info.rcv_sid;
  printf("verify_data(sid=%d)\n", sid);
  fflush(stdout);
  if (len >= sizeof(struct data_desc)) {
    struct data_desc *desc = (struct data_desc*) buffer;
    if (desc->assoc != assoc_id(assoc) || desc->sid != sid) {
      fail(assoc, sid, "Wrong data descriptor for buffer, assoc: %d, sid: %d",
           assoc_id(assoc), desc->sid);
    }
  } else if (len >= sizeof(int)) {
    uint32_t key = assoc_id(assoc) ^ sid;
    if (key != *(uint32_t*) buffer) {
      fail(assoc, sid, "Wrong data key for buffer, assoc: %d, sid: %d, key: %d",
           assoc_id(assoc), sid, key);
    }
  }
  printf("Verify Data LOCK (sid %d) {", sid);
  pthread_mutex_lock(&cond_lock);
  sid_counts[sid]++;
  if (sid_counts[sid] > max_sid_usage) {
    printf("** WARN: sid %d has a higher count (%d) than max_sid_usage (%d)!\n",
           sid, sid_counts[sid], max_sid_usage);
  }
  pthread_cond_signal(&cond_counter);
  pthread_mutex_unlock(&cond_lock);
  printf("} Verify Data UNLOCK (sid %d)\n", sid);
  free(buffer);
  return 1;
}

// * Utilities

void fail(struct socket * assoc, int sid, const char *message, ...) {
#define BUF_LEN (200)
  char prefix_buf[BUF_LEN];
  char message_buf[BUF_LEN];
  va_list args;

  snprintf(prefix_buf, BUF_LEN, "FAIL: Assoc %d, SID %d: ",
           assoc_id(assoc), sid);
  va_start(args, message);
  vsnprintf(message_buf, BUF_LEN, message, args);
  va_end(args);

  struct iovec ops[3];
  ops[0].iov_base = prefix_buf;
  ops[0].iov_len = strlen(prefix_buf);
  ops[1].iov_base = message_buf;
  ops[1].iov_len = strlen(message_buf);
  ops[2].iov_base = "\n";
  ops[2].iov_len = 1;
  write(2, ops, 3);  // stderr
  exit(1);
}

enum DestType {
  dstLocalhost,
  dstAny
};

void fill_localhost(struct sockaddr_in *dest, int port, enum DestType type) {
  bzero(dest, sizeof(struct sockaddr_in));
  dest->sin_family = AF_INET;
  dest->sin_port = htons(port);
  if (type == dstLocalhost) {
    int ret = inet_pton(AF_INET, "127.0.0.1", &dest->sin_addr);
    CHECK(ret);
  } else {
    dest->sin_addr.s_addr = htonl(INADDR_ANY);
  }
#ifdef HAVE_SIN_LEN
  dest->sin_len = sizeof(struct sockaddr_in);
#endif
}

int setup_udp_socket (int port) {
  int udp_fd;
  intptr_t udp_fd_p;
  pthread_t tid;
  struct sockaddr_in localhost;
  struct fd_info *info;
  if ((udp_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    perror("socket");
    exit(1);
  }
  if (port < 0) {
    printf("setup_udp_socket: Binding to port %d for socket %d\n", -port, udp_fd);
    fill_localhost(&localhost, -port, dstLocalhost);

    if (bind(udp_fd, (struct sockaddr *)&localhost, sizeof(struct sockaddr_in)) < 0) {
      perror("bind");
      exit(1);
    }
  } else {
    printf("setup_udp_socket: Connecting to port %d for socket %d\n", port, udp_fd);
    fill_localhost(&localhost, port, dstLocalhost);
    if (connect(udp_fd, (struct sockaddr *)&localhost, sizeof(struct sockaddr_in)) < 0) {
      perror("connect");
      exit(1);
    }
  }

  info = (struct fd_info*) malloc(sizeof (struct fd_info));
  info->port = htons(port > 0? port:-port);
  info->udp_fd = udp_fd;
  pthread_mutex_lock(&client_list_lock);
  TAILQ_INSERT_HEAD(&all_clients, info, entries);
  pthread_mutex_unlock(&client_list_lock);

  return udp_fd;
}

void bind_addr_pairs(int first_fd, int second_fd) {
  struct sockaddr_in first_addr, second_addr;
  socklen_t first_addr_len, second_addr_len;
  struct fd_info *inf;
  int ret;
  first_addr_len = second_addr_len = sizeof(struct sockaddr_in);
  ret = getsockname(first_fd, (struct sockaddr*) &first_addr, &first_addr_len);
  CHECK(ret == 0);
  ret = getsockname(second_fd, (struct sockaddr*) &second_addr, &second_addr_len);
  CHECK(ret == 0);

  ret = 0;
  pthread_mutex_lock(&client_list_lock);
  for (inf = all_clients.tqh_first; inf != NULL; inf = inf->entries.tqe_next) {
    if (inf->udp_fd == first_fd) {
      inf->peer_addr = second_addr;
      inf->peer_fd = second_fd;
      ret++;
    } else if (inf->udp_fd == second_fd) {
      inf->peer_addr = first_addr;
      inf->peer_fd = first_fd;
      ret++;
    }
  }
  pthread_mutex_unlock(&client_list_lock);
  CHECK(ret == 2);
}

// Chooses a SID and sends data on it.
void send_data_on_sock(const char *prefix, struct op_shared_sock *sock) {
  int sid = choose_unused_sid();
  printf("%s: %d\n", prefix, sid);
  send_some_data(sock, sid, SEND_SIZE);
}

// * Client Thread

struct client_info {
  struct fd_info local, remote;
};

void *client_thread(void *info_p) {
  struct socket *client_sock;
  struct sockaddr_conn localhost;
  int ret, i;
  struct client_info *info = (struct client_info*) info_p;
  struct op_shared_sock *shared_sock;
  /* Create a socket over our local (client) fd, and then connect to
     the remote (server) fd */
  puts("C: client_sock");
  fflush(stdout);
  client_sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                               verify_data, NULL, 0, (void*) info->local.udp_fd);
  if (client_sock == NULL) {
    perror("C: usrsctp_socket");
  }
  CHECK(client_sock);

  printf("C: client connect to port %d\n", info->remote.port);
  fflush(stdout);

  bzero(&localhost, sizeof(struct sockaddr_conn));
  localhost.sconn_family = AF_CONN;
  localhost.sconn_port = info->remote.port;
  //  localhost.sconn_port = htons(info->remote.port);
  localhost.sconn_addr = (void*) info->local.udp_fd;
#ifdef HAVE_SCONN_LEN
  localhost.sconn_len = sizeof(struct sockaddr_conn);
#endif
  ret = usrsctp_connect(client_sock, (struct sockaddr*) &localhost,
                        sizeof(struct sockaddr_conn));
  if (ret < 0) {
    perror("C: usrsctp_connect");
    return NULL;
  }
  CHECK(!ret);

  shared_sock = wrap_socket(client_sock);

  for (i = 0; i < (NUM_SIDS / 2); i++) {
    send_data_on_sock("C client ", shared_sock);
  }
  puts("C: client finish");
  return NULL;
}

// * Test Runner and Server-side of network link

int run_single_test (int port) {
  struct socket *server_sock, *client_sock, *server_listen_sock;
  struct sockaddr_conn localhost;
  int ret, fin_cnt = 0, i;
  int server_udp_fd, client_udp_fd;
  intptr_t server_fd_handle, client_fd_handle;
  pthread_t child;
  struct client_info c_info;
  int go_again = 1;
  int run_threshold = 1;
  struct timespec wait;
  struct op_shared_sock *shared_server_sock;

  // usrsctp initialization - We have to set up a UDP pipe in, and
  // out, over a single UDP socket for I/O to/from the library.  This
  // pipe's FD has to be somehow registered with usrsctp.

  puts("S: init");

  // Setup the udp sockets.
  server_udp_fd = setup_udp_socket(-port);
  client_udp_fd = setup_udp_socket(port);

  printf("Server FD is %d\nClient FD is %d\n", server_udp_fd, client_udp_fd);
  server_fd_handle = server_udp_fd;
  client_fd_handle = client_udp_fd;

  bind_addr_pairs(server_udp_fd, client_udp_fd);

  usrsctp_register_address((void *) server_fd_handle);
  usrsctp_register_address((void *) client_fd_handle);
  /* usrsctp_sysctl_set_sctp_ecn_enable(0); */

  /* Bind and Listen on the server socket */
  puts("S: server_listen_sock");
  server_listen_sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                                      verify_data, NULL, 0, 
                                      (void*) server_fd_handle);
  CHECK(server_listen_sock != NULL);

  bzero(&localhost, sizeof(struct sockaddr_conn));
  localhost.sconn_port = htons(port);
  localhost.sconn_addr = (void*) server_fd_handle;
  localhost.sconn_family = AF_CONN;
  puts("S: bind");
  ret = usrsctp_bind(server_listen_sock,
                     (struct sockaddr*) &localhost, sizeof(struct sockaddr_conn));
  if (ret < 0) {
    perror("S: usrsctp_bind");
  }
  CHECK(!ret);

  puts("S: listen");
  ret = usrsctp_listen(server_listen_sock, 1);
  if (ret != 0) {
    perror("S: usrsctp_listen");
  }
  CHECK(!ret);

  puts("S: create child for client");
  c_info.local.port = htons(port);
  c_info.local.udp_fd = client_udp_fd;
  c_info.remote.port = htons(port);
  c_info.remote.udp_fd = server_udp_fd;
  ret = pthread_create(&child, NULL, client_thread, (void*) &c_info);
  CHECK(!ret);

  puts("S: server_accept");
  server_sock = usrsctp_accept(server_listen_sock, NULL, NULL);
  if (server_sock == NULL) {
    perror("S: usrsctp_accept");
  }
  CHECK(server_sock);
  shared_server_sock = wrap_socket(server_sock);

  for (i = 0; i < NUM_SIDS / 2; i++) {
    send_data_on_sock("S: server ", shared_server_sock);
  }

  puts("S: waiting for I/O to complete.");
  /* Await for a certain number (run_threshold) of verified packets (via
     verify_data) to have come in on each PPID. */
  while (go_again) {
    putchar('.');
    do {
      clock_gettime(CLOCK_REALTIME, &wait);
      wait.tv_sec += 2;  // wait 2 sec.
    } while (pthread_cond_timedwait(&cond_counter, &cond_lock, &wait) == EAGAIN);

    go_again = 0;
    printf("<< COMPLETED SIDS:");
    for (i = 0; i < NUM_SIDS; i++) {
      if (sid_counts[i] < run_threshold) {
        go_again = 1;
      } else {
        printf(" [%d: %d]", i, sid_counts[i]);
      }
    }
    pthread_mutex_unlock(&cond_lock);
    printf(">> \n");
  }

  puts("S: closing");
  sctp_close(server_sock);
  while (sctp_finish()) {
    putchar('#');
    fin_cnt++;
  }
  printf("\n++++++++++++++++++++++++++ FINISHED ++++++++++++++++++++++++++\n");
  return fin_cnt;
}


int main(int argc, char **argv) {
  pthread_t packet_handler, queue_runner;
  if (argc > 1) {
    s_num_sids = atoi(argv[1]);
  }

  if (s_num_sids > MAX_NUM_SIDS) {
    printf("FAIL: argument 1 is too large.  max is %d\n", MAX_NUM_SIDS);
  }

  if (argc > 2) {
    s_send_size = atoi(argv[2]);
  }

  if (s_send_size > MAX_SEND_SIZE) {
    printf("FAIL: argument 2 is too large.  max is %d\n", MAX_SEND_SIZE);
  }

  TAILQ_INIT(&op_q_head);
  TAILQ_INIT(&all_clients);

  op_queue_state = qsOPEN;
  usrsctp_init(0, conn_output, debug_printf);
  usrsctp_sysctl_set_sctp_blackhole(2);
  /* 10 is the usrsctp default */
  if (NUM_SIDS > 10) {
    usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(NUM_SIDS);
  }
  pthread_create(&packet_handler, NULL, &handle_packets, NULL);

  pthread_create(&queue_runner, NULL, &run_closure_queue, NULL);
#ifdef SCTP_DEBUG
  usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif

  run_single_test(9000);

  // listen on port PORT
  // connect to port.
  // send data
  // verify it was received.
  // send data the other way.
  // verify it was received.
  // restart.
  return 0;
}
