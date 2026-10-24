/* Polaris read-only log/panel snapshots over the admitted USB ECM link.
 * One worker owns its snapshot. No command, address or storage API exists.
 */
#if defined(POLARIS_RAM_ONLY)
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <mach/thread_act.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <vm/vm_kern.h>
#include <pexpert/pexpert.h>
#include "polaris_debug_wire.h"

extern uint32_t sweet_log_copy(uint64_t *, char *, uint32_t);
extern uint64_t sweet_log_position(void);
extern bool polaris_usb_connected(void);
extern uint32_t polaris_debug_frame(void *, uint32_t);
void polaris_debug_start(void);
static uint32_t pdbg_started;
static int pdbg_wait;

static void pdbg_sleep(void)
{
    uint64_t deadline;
    clock_interval_to_deadline(10, NSEC_PER_MSEC, &deadline);
    (void)assert_wait_deadline(&pdbg_wait, THREAD_UNINT, deadline);
    thread_block(THREAD_CONTINUE_NULL);
}

static void pdbg_worker(void *arg __unused, wait_result_t wr __unused)
{
    socket_t so = NULL;
    struct sockaddr_in local;
    struct pdbg_snapshot snapshot = {0};
    vm_offset_t storage = 0;
    uint8_t request[PDBG_REQUEST_BYTES + 1], reply[PDBG_REPLY_BYTES + PDBG_CHUNK];
    bzero(&local, sizeof(local));
    local.sin_len = sizeof(local); local.sin_family = AF_INET;
    local.sin_port = htons(5141); local.sin_addr.s_addr = htonl(0xc0a80702);
    if (sock_socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, NULL, &so) ||
        sock_bind(so, (struct sockaddr *)&local)) {
        if (so) sock_close(so);
        thread_terminate(current_thread());
        return;
    }
    for (;;) {
        if (!polaris_usb_connected()) { pdbg_sleep(); continue; }
        struct sockaddr_in peer;
        bzero(&peer, sizeof(peer));
        struct iovec in = {.iov_base = request, .iov_len = sizeof(request)};
        struct msghdr msg = {.msg_name = &peer, .msg_namelen = sizeof(peer),
            .msg_iov = &in, .msg_iovlen = 1};
        size_t received = 0;
        errno_t error = sock_receive(so, &msg, MSG_DONTWAIT, &received);
        if (error) { pdbg_sleep(); continue; }
        struct pdbg_request r;
        if (peer.sin_family != AF_INET || peer.sin_addr.s_addr != htonl(0xc0a80701) ||
            msg.msg_flags & MSG_TRUNC || !pdbg_parse(request, received, &r)) continue;
        unsigned status = PDBG_OK;
        uint32_t bytes = 0;
        if (r.op != PDBG_READ) {
            if (snapshot.token == r.token) {
                /* Retry the same capture token without changing its contents. */
                if (snapshot.kind != r.op) status = PDBG_BAD;
            } else {
                snapshot = (struct pdbg_snapshot){0};
                if (!storage && kmem_alloc(kernel_map, &storage, PDBG_FRAME_BYTES,
                    KMA_DATA | KMA_ZERO | KMA_PERMANENT, VM_KERN_MEMORY_IOKIT) != KERN_SUCCESS)
                    status = PDBG_NOMEM;
                if (status == PDBG_OK) {
                    if (r.op == PDBG_LOG) {
                        uint64_t end = sweet_log_position();
                        uint64_t pos = end > PDBG_LOG_LIMIT ? end - PDBG_LOG_LIMIT : 0;
                        bytes = sweet_log_copy(&pos, (char *)storage, (uint32_t)(end - pos));
                        snapshot = (struct pdbg_snapshot){.token = r.token,
                            .bytes = bytes, .kind = PDBG_LOG};
                    } else {
                        bytes = polaris_debug_frame((void *)storage, PDBG_FRAME_BYTES);
                        if (bytes != PDBG_FRAME_BYTES) status = PDBG_NOT_READY;
                        else snapshot = (struct pdbg_snapshot){.token = r.token,
                            .bytes = bytes, .kind = PDBG_FRAME, .width = 1080,
                            .height = 2160, .stride = 4320};
                    }
                }
            }
            bytes = 0;
        } else if (!pdbg_span(&snapshot, &r)) status = PDBG_STALE;
        else {
            bytes = r.length;
            memcpy(reply + PDBG_REPLY_BYTES, (const uint8_t *)storage + r.offset, bytes);
        }
        if (!pdbg_reply(reply, &snapshot, &r, status, reply + PDBG_REPLY_BYTES, bytes)) continue;
        struct iovec out = {.iov_base = reply, .iov_len = PDBG_REPLY_BYTES + bytes};
        struct msghdr response = {.msg_name = &peer, .msg_namelen = sizeof(peer),
            .msg_iov = &out, .msg_iovlen = 1};
        size_t sent = 0;
        (void)sock_send(so, &response, MSG_DONTWAIT, &sent);
        /* No printf here: it would feed the log being transferred. */
    }
}

void polaris_debug_start(void)
{
    unsigned enabled = 0;
    PE_parse_boot_argn("polarisdebug", &enabled, sizeof(enabled));
    if (enabled != 1 || __atomic_exchange_n(&pdbg_started, 1, __ATOMIC_ACQ_REL)) return;
    thread_t thread;
    if (kernel_thread_start(pdbg_worker, NULL, &thread) == KERN_SUCCESS) {
        thread_deallocate(thread);
        printf("POLARIS DEBUG: USB log/panel snapshots, UDP5141; no command service\n");
    }
}
#endif
