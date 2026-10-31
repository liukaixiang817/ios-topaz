#!/usr/bin/env python3
"""Extract actual profile0908 journal functions into a software buf-error
fixture. Counter/error/retirement assertions do not prove physical storage,
RAMCOW or the captured panic's caller. Native compilation is a separate check.
"""
from pathlib import Path
import argparse
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    at = source.index("\n" + name + "(")
    start = source.rfind("\n", 0, at) + 1
    opening = source.index("{", at)
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-tree", type=Path, default=ROOT / "research/polaris/buildtree-0004/xnu")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="polaris-hfs-journal-") as directory:
        temp = Path(directory)
        core = temp / "bsd/sweet_hfs/core"
        core.mkdir(parents=True)
        for name in ("hfs_journal.c", "hfs_journal.h"):
            shutil.copyfile(args.source_tree / "bsd/sweet_hfs/core" / name, core / name)
        subprocess.run(["patch", "--silent", "-p1", "-d", str(temp), "-i", str(ROOT /
            "xnu/profiles/polaris/0908-polaris-HFS-async-metadata-error-propagation.patch")], check=True)
        source = (core / "hfs_journal.c").read_text()
        extracted = "\n\n".join(function(source, name) for name in (
            "polaris_journal_io_error", "polaris_journal_invalid", "buffer_flushed_callback", "journal_end_transaction", "journal_flush"))
        (temp / "actual-functions.h").write_text(extracted)
        (temp / "check.c").write_text(HARNESS)
        subprocess.run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
            "-Wno-unused-function", "-fsanitize=address,undefined", "-pthread", str(temp / "check.c"),
            "-o", str(temp / "check")], check=True)
        subprocess.run([str(temp / "check")], check=True)


HARNESS = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#define TRUE 1
#define FALSE 0
#define JOURNAL_INVALID 0x00020000
#define JOURNAL_WAIT_FOR_IO 1
#define JOURNAL_FLUSH_FULL 2
#define ISSET(x,y) ((x)&(y))
#define CHECK_JOURNAL(x) assert(x)
#define CHECK_TRANSACTION(x) assert(x)
#define KDBG(...) ((void)0)
#define FWRITE 2
#define DKIOCSYNCHRONIZE 1
typedef int boolean_t,errno_t,journal_flush_options_t;
typedef struct {int options;} dk_synchronize_t;
typedef struct journal journal;
typedef struct transaction transaction;
struct transaction {
    int total_bytes,num_flushed,num_killed,flush_on_completion;
    off_t journal_start,journal_end;
    transaction *next;
    journal *jnl;
};
struct journal {
    int flags,async_write_error,flush_aborted,asyncIO,flushing,locks,nested_count;
    uint32_t flush_counter;
    void *owner,*jdev,*fsdev;
    transaction *completed_trs,*tr_freeme,*active_tr,*cur_tr;
    uint64_t old_start[16];
    off_t active_start;
    pthread_mutex_t old_lock;
};
struct buf {int bytes,error;};
static unsigned checks,unlocks,frees,ioctls,aborts;
static int ioctl_first_error,ioctl_second_error;
static struct buf *inject_buf;
static transaction *inject_tr;
static int buf_size(struct buf *bp){return bp->bytes;}
static int buf_error(struct buf *bp){return bp->error;}
static int OSAddAtomic(int value,int *p){return __atomic_fetch_add(p,value,__ATOMIC_ACQ_REL);}
static void lock_oldstart(journal *j){assert(!pthread_mutex_lock(&j->old_lock));}
static void unlock_oldstart(journal *j){assert(!pthread_mutex_unlock(&j->old_lock));}
static void unlock_condition(journal *j,boolean_t *condition)
{(void)j;*condition=FALSE;unlocks++;}
static void panic(const char *s,...){(void)s;abort();}
static void *current_thread(void){return (void *)(uintptr_t)1;}
static void journal_lock(journal *j){j->locks++;}
static void journal_unlock(journal *j){j->locks--;assert(j->locks>=0);}
static void free_old_stuff(journal *j)
{while(j->tr_freeme){transaction *t=j->tr_freeme;j->tr_freeme=t->next;frees++;}}
static int end_transaction(transaction *t,int f,void *cb,void *arg,boolean_t drop,boolean_t wait)
{(void)f;(void)cb;(void)arg;(void)wait;if(drop)journal_unlock(t->jnl);return 0;}
static void abort_transaction(journal *j,transaction *t){(void)j;(void)t;aborts++;}
static void buffer_flushed_callback(struct buf *,void *);
static void wait_condition(journal *j,boolean_t *condition,const char *name)
{
    (void)name;
    if(condition==&j->asyncIO && *condition && inject_buf) {
        struct buf *bp=inject_buf;transaction *t=inject_tr;inject_buf=NULL;
        buffer_flushed_callback(bp,t);
    }
    assert(!*condition);
}
static void *vfs_context_kernel(void){return NULL;}
static int VNOP_IOCTL(void *v,int op,void *request,int flags,void *context)
{(void)v;(void)op;(void)request;(void)flags;(void)context;ioctls++;return ioctls==1?ioctl_first_error:ioctl_second_error;}
#include "actual-functions.h"
#define CHECK(x) do {assert(x);checks++;}while(0)
static void init(journal *j,transaction *t,unsigned buffers)
{
    *j=(journal){0};assert(!pthread_mutex_init(&j->old_lock,NULL));
    *t=(transaction){.total_bytes=512+(int)buffers*8192,.num_flushed=512,
        .journal_start=4096,.journal_end=16384,.jnl=j};
    j->active_start=4096;j->old_start[0]=UINT64_C(0x8000000000001000);
    j->asyncIO=TRUE;j->jdev=j;j->fsdev=j;
    unlocks=frees=ioctls=aborts=0;ioctl_first_error=ioctl_second_error=0;inject_buf=NULL;
}
static void complete_order(bool error_first)
{
    journal j;transaction t;init(&j,&t,2);
    struct buf bad={8192,ENOSPC},good={8192,0};
    buffer_flushed_callback(error_first?&bad:&good,&t);
    CHECK(!unlocks && !j.tr_freeme && j.asyncIO);
    if(error_first)CHECK(j.async_write_error==ENOSPC && j.flags&JOURNAL_INVALID && j.flush_aborted);
    buffer_flushed_callback(error_first?&good:&bad,&t);
    CHECK(j.async_write_error==ENOSPC && bad.error==ENOSPC && !good.error);
    CHECK(t.num_flushed==512+16384 && !j.asyncIO && unlocks==1);
    CHECK(j.old_start[0]==UINT64_C(0x8000000000001000) && j.active_start==4096);
    CHECK(j.tr_freeme==&t && !j.completed_trs && !frees);
    CHECK(journal_flush(&j,JOURNAL_WAIT_FOR_IO|JOURNAL_FLUSH_FULL)==ENOSPC && !ioctls);
    CHECK(frees==1 && !j.tr_freeme);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
}
static void success_and_prior_completed(void)
{
    journal j;transaction t;init(&j,&t,1);struct buf bp={8192,0};
    buffer_flushed_callback(&bp,&t);
    CHECK(!j.async_write_error && !(j.flags&JOURNAL_INVALID));
    CHECK(j.active_start==16384 && j.old_start[0]==4096 && j.tr_freeme==&t && !j.asyncIO);
    buffer_flushed_callback(&bp,&t);CHECK(unlocks==1); /* duplicate already-completed callback */
    CHECK(journal_flush(&j,JOURNAL_WAIT_FOR_IO)==0 && frees==1);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
    init(&j,&t,1);transaction previous={.next=NULL},earlier={.next=&previous};j.completed_trs=&earlier;
    bp.error=EIO;buffer_flushed_callback(&bp,&t);
    CHECK(j.active_start==4096 && !j.completed_trs);
    free_old_stuff(&j);CHECK(frees==3 && !j.tr_freeme);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
}
static void first_error_and_flags_race(void)
{
    journal j;transaction t;init(&j,&t,3);
    struct buf first={8192,ENOSPC},second={8192,EIO},last={8192,0};
    buffer_flushed_callback(&first,&t);buffer_flushed_callback(&second,&t);
    CHECK(j.async_write_error==ENOSPC && first.error==ENOSPC && second.error==EIO);
    CHECK(!unlocks && j.asyncIO && !j.tr_freeme);
    j.flags=0; /* a legacy flags writer must not lose the separate sticky errno */
    CHECK(polaris_journal_invalid(&j));
    buffer_flushed_callback(&last,&t);
    CHECK(j.active_start==4096 && j.old_start[0]==UINT64_C(0x8000000000001000));
    CHECK(j.tr_freeme==&t && !j.asyncIO && unlocks==1);
    CHECK(journal_flush(&j,JOURNAL_WAIT_FOR_IO|JOURNAL_FLUSH_FULL)==ENOSPC && !ioctls);
    CHECK(frees==1);CHECK(!pthread_mutex_destroy(&j.old_lock));
}
static void wait_and_ioctl_error(void)
{
    journal j;transaction t;init(&j,&t,1);struct buf bp={8192,ENOSPC};
    inject_buf=&bp;inject_tr=&t;
    CHECK(journal_flush(&j,JOURNAL_WAIT_FOR_IO|JOURNAL_FLUSH_FULL)==ENOSPC);
    CHECK(j.async_write_error==ENOSPC && !ioctls && !j.asyncIO && !j.locks);
    CHECK(bp.error==ENOSPC && j.active_start==4096);
    free_old_stuff(&j);CHECK(frees==1);CHECK(!pthread_mutex_destroy(&j.old_lock));
    init(&j,&t,1);j.asyncIO=FALSE;ioctl_first_error=EIO;ioctl_second_error=ENOSPC;j.fsdev=&t;
    CHECK(journal_flush(&j,JOURNAL_FLUSH_FULL)==EIO && ioctls==2 && !j.locks);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
    init(&j,&t,1);j.flags=JOURNAL_INVALID;
    CHECK(journal_flush(&j,JOURNAL_WAIT_FOR_IO)==EIO && !ioctls);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
}
static void end_transaction_retains_errno(void)
{
    journal j;transaction t;init(&j,&t,1);struct buf bp={8192,ENOSPC};
    buffer_flushed_callback(&bp,&t);CHECK(!aborts);
    CHECK(journal_end_transaction(&j)==ENOSPC && frees==1 && !aborts);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
    init(&j,&t,1);j.async_write_error=ENOSPC;j.owner=current_thread();j.nested_count=1;j.locks=1;j.active_tr=&t;
    CHECK(journal_end_transaction(&j)==ENOSPC && aborts==1 && !j.active_tr && !j.locks);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
    init(&j,&t,1);j.owner=current_thread();j.nested_count=1;j.locks=1;j.active_tr=&t;
    CHECK(journal_end_transaction(&j)==0 && !aborts && !j.active_tr && !j.locks);
    CHECK(!pthread_mutex_destroy(&j.old_lock));
}
struct work {struct buf bp;transaction *tr;};
static void *run(void *arg){struct work *w=arg;buffer_flushed_callback(&w->bp,w->tr);return NULL;}
static void parallel_completions(void)
{
    enum {N=32};journal j;transaction t;init(&j,&t,N);
    struct work work[N];pthread_t thread[N];
    for(unsigned i=0;i<N;i++) {work[i]=(struct work){{8192,i==0?ENOSPC:0},&t};CHECK(!pthread_create(&thread[i],NULL,run,&work[i]));}
    for(unsigned i=0;i<N;i++)CHECK(!pthread_join(thread[i],NULL));
    CHECK(j.async_write_error==ENOSPC && t.num_flushed==512+N*8192);
    CHECK(j.old_start[0]==UINT64_C(0x8000000000001000) && j.active_start==4096);
    CHECK(!j.asyncIO && unlocks==1 && j.tr_freeme==&t && !frees);
    CHECK(work[0].bp.error==ENOSPC && !work[N-1].bp.error);
    free_old_stuff(&j);CHECK(frees==1);CHECK(!pthread_mutex_destroy(&j.old_lock));
}
int main(void)
{
    complete_order(true);complete_order(false);success_and_prior_completed();first_error_and_flags_race();
    wait_and_ioctl_error();end_transaction_retains_errno();parallel_completions();
    printf("PASS %u actual HFS callback/flush software assertions; no physical I/O\n",checks);
    return 0;
}
'''


if __name__ == "__main__":
    main()
