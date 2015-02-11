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

typedef void (*op_fn)(void* context);

TAILQ_HEAD(op_closure_head, op_closure) op_q_head;

struct op_closure {
  TAILQ_ENTRY(op_closure) entries;
  op_fn opc_fun;
  void* opc_context;
};

pthread_mutex_t op_queue_lock = PTHREAD_MUTEX_INITIALIZER;
enum QueueState { qsOPEN, qsCLOSING } op_queue_state;
pthread_cond_t *op_queue_sig;

struct op_closure* get_next_op() {
  return NULL;
}

void run_closure_queue () {
  struct op_closure* op;
  // Can block getting another item from the queue, and will kill the
  // thread when the queue's dying, by returning NULL.
  op = get_next_op();
  if (op == NULL) {
    return;
  } else if (!op->opc_fun) {
    fprintf(stderr, "Bad closure, no function @ %p\n", op);
  } else {
    op->opc_fun(op->opc_context);
  }
  free(op);
}

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

  printf("[Output %ld bytes: addr=%p buf=%p tos=%x set_df=%x]",
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

  if ((dump_buf = usrsctp_dumppacket(buf, length,
                                     SCTP_DUMP_OUTBOUND)) != NULL) {
    fprintf(stderr, "%s", dump_buf);
    usrsctp_freedumpbuffer(dump_buf);
  }

  printf("(W): send(%d): %ld bytes to %s:%d\n", fdp, length,
         inet_ntop(AF_INET, &peer.sin_addr, ipbuf, 64),
         htons(peer.sin_port));
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
    io_bufp = io_buf +
      snprintf(io_buf, MAX_PACKET_SIZE, "(IO): select(2) on UDP fds ");

    max_fd = -1;

    pthread_mutex_lock(&client_list_lock);
    for (inf = all_clients.tqh_first; inf != NULL; inf = inf->entries.tqe_next) {
      int fd = inf->udp_fd;
      io_bufp += snprintf(io_bufp, MAX_PACKET_SIZE - (io_bufp - io_buf),
                          (inf != all_clients.tqh_first? ", %d" : "%d"), fd);
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

    //    puts(io_buf);
    nr = select(max_fd + 1, &fdset, NULL, NULL, &tmout);
    //    printf("(IO): select returned %d\n", nr);
    if (nr < 0) {
      perror("select");
      sleep(1);
    }

    if (nr) {
      //      printf("(IO): select(2) returned %d\n", nr);
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
        printf("(IO): %ld input on fd %d\n  IP: %s:%d\n  Peer IP: %s:%d\n",
               io_length, fd,
               inet_ntop(AF_INET, &sock_addr.sin_addr, ipbuf, 32),
               ntohs(sock_addr.sin_port),
               inet_ntop(AF_INET, &fds[i].peer_addr.sin_addr, ipbuf2, 32),
               ntohs(fds[i].peer_addr.sin_port));
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


void send_some_data(struct socket* assoc, int sid, int len) {
  uint8_t *buffer = (uint8_t*) malloc(len);
  uint8_t *buf_end = buffer + len;
  uint32_t key = assoc_id(assoc) ^ sid;
  uint32_t *bufkey = (uint32_t*) buffer;
  uint32_t *bufkey_end = bufkey + (len / 4);
  uint8_t *buf_last = buffer + len - (len % 4);
  int i, ret;
  struct sctp_sndinfo sndinfo;

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
  sndinfo.snd_context = key;

  ret = usrsctp_sendv(assoc, buffer, len, NULL, 0, &sndinfo,
                      sizeof(struct sctp_sndinfo), SCTP_SENDV_SNDINFO, 0);
  CHECK(ret);
  free(buffer);
}


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

/* lots of open questions on thread boundaries here! */
static int ppid_counts[8];

/* Assume same endian-ness on both machines.  Otherwise, fix this. */
int verify_data(struct socket *assoc,
                union sctp_sockstore addr,
                void *buffer,
                size_t len,
                struct sctp_rcvinfo info,
                int flags,
                void *wtf_is_this) {
  int sid = info.rcv_sid;
  printf("verify_data(sid=%d): sctp_sockstore is %ld bytes long.\n", sid, sizeof(union sctp_sockstore));
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
  ppid_counts[info.rcv_ppid]++;
  free(buffer);
  return 1;
}

struct client_info {
  struct fd_info local, remote;
};


void *client_thread(void *info_p) {
  struct socket *client_sock;
  struct sockaddr_conn localhost;
  int ret;
  struct client_info *info = (struct client_info*) info_p;

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

  puts("C: client send"); fflush(stdout);
  send_some_data(client_sock, 0, 500);
  puts("C: client finish");
  return NULL;
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

int run_single_test (int port) {
  struct socket *server_sock, *client_sock, *server_listen_sock;
  struct sockaddr_conn localhost;
  int ret, fin_cnt;
  int server_udp_fd, client_udp_fd;
  intptr_t server_fd_handle, client_fd_handle;
  pthread_t child;
  struct client_info c_info;

  fin_cnt = 0;

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

  puts("S: server send"); fflush(stdout);
  send_some_data(server_sock, 1, 500);

  puts("S: waiting for I/O to complete.");
  while (ppid_counts[0] == 0 && ppid_counts[1] == 0) {
    putchar('.');
  }

  puts("S: closing");
  sctp_close(server_sock);
  while (sctp_finish()) {
    putchar('#');
    fin_cnt++;
  }
  return fin_cnt;
}


int main() {
  pthread_t packet_handler;
  usrsctp_init(0, conn_output, debug_printf);
  usrsctp_sysctl_set_sctp_blackhole(2);
  pthread_create(&packet_handler, NULL, &handle_packets, NULL);

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
