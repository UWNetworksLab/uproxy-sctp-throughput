#include <stdio.h>
#include <usrsctp.h>
#include <pthread.h>
#include <sys/queue.h>

typedef void (*op_fn)(void* context);

TAILQ_HEAD(op_closure_head, op_closure) op_q_head;
struct op_closure {
  TAILQ_ENTRY(op_closure) entries;
  op_fn opc_fun;
  void* opc_context;
}

pthread_mutex_t *op_queue_lock;

void run_closure_queue {
  op_closure* op;
  // Can block getting another item from the queue, and will kill the
  // thread when the queue's dying.
  op = get_next_op();
  if (!op->opc_fun) {
    fprintf(stderr, "Bad closure, no function @ %p\n", op);
  } else {
    op->opc_fun(op->opc_context);
  }
  free(op);
}

