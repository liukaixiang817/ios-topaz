/*
MIT License

Copyright (c) 2026 yanei and dipper-xnu contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

 * Adapted for Polaris from dipper-xnu e930c26 bsd/dev/mi8_glink.c.
 * Changes: bounded nonwaiting gate, checked scoped I/O, explicit cache/order,
 * append-only sticky error counters, zero-based remote intents, finite send
 * budget, peer discovery, and CLOSE_ACK/FIFO/intents drain before release.
 * No SMEM getter/allocator, mapping, MPU change, ICNSS/radio power, or DMA.
 */
#include "polaris-wifi-glink.h"

#ifdef POLARIS_WIFI_GLINK_HOST_TEST
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#define PWF_THREAD_ID() ((uintptr_t)pthread_self())
#ifndef PWF_ALLOC
#define PWF_ALLOC(n) calloc(1, (n))
#define PWF_FREE(p, n) free(p)
#endif
#else
#include <sys/errno.h>
#include <libkern/libkern.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#ifndef PWF_THREAD_ID
#define PWF_THREAD_ID() ((uintptr_t)current_thread())
#endif
#ifndef PWF_ALLOC
#define PWF_ALLOC(n) kalloc_data((n), Z_WAITOK | Z_ZERO)
#define PWF_FREE(p, n) kfree_data((p), (n))
#endif
#endif

#define INSTANCES 8
#define PORTS 16
#define LOOKUPS 16
#define SERVERS 64
#define INTENTS 64
#define MAX_PACKET 65536u
#define WAIT_US 5000000u
#define CTRL 0xfffffffeu
#define BCAST 0xffffffffu
#define RESERVE 16u
#define LOG(g, ...) do { if ((g)->cfg.log) (g)->cfg.log((g)->cfg.ctx, __VA_ARGS__); } while (0)

enum {
	VERSION = 0, VERSION_ACK = 1, OPEN = 2, CLOSE = 3, OPEN_ACK = 4,
	INTENT = 5, DONE = 6, INTENT_REQ = 7, INTENT_ACK = 8, DATA = 9,
	CLOSE_ACK = 11, DATA_MORE = 12, READ_NOTIFY = 13, DONE_REUSE = 14, SIGNALS = 15
};
enum {
	Q_DATA = 1, Q_HELLO = 2, Q_BYE = 3, Q_NEW_SERVER = 4, Q_DEL_SERVER = 5,
	Q_DEL_CLIENT = 6, Q_RESUME = 7, Q_NEW_LOOKUP = 10, Q_DEL_LOOKUP = 11
};

struct intent {
	uint32_t id, size, fill, left;
	bool there, busy, reusable;
	uint8_t *data;
};
struct lookup {
	bool used;
	uint32_t service, version, instance;
};
struct polaris_wifi_qrtr_port {
	struct polaris_wifi_glink *g;
	bool live;
	uint32_t id, generation;
	polaris_wifi_qrtr_receive_t receive;
	polaris_wifi_qrtr_server_t server;
	void *ctx;
	struct lookup lookups[LOOKUPS];
	bool published;
	uint32_t service, version, instance;
};
struct command {
	struct command *next;
	uint32_t length;
	uint8_t bytes[48];
};
struct outgoing {
	struct outgoing *next;
	uint32_t length, offset, iid;
	uint64_t since;
	int error;
	bool requested, answered, granted, synchronous, done, has_intent;
	uint8_t bytes[];
};
struct polaris_wifi_glink {
	struct polaris_wifi_glink_cfg cfg;
	uintptr_t owner;
	unsigned depth, slot;
	uint32_t desc, tx, tx_size, rx, rx_size;
	bool up, broken, agreed, asked, acked, opened, closing, hello;
	bool stop_requested, started, uncertain, close_confirmed;
	uint32_t first_error, detail, writes, rings, reads, cache_ops;
	uint64_t last_us;
	bool notified;
	uint32_t notify_tail, features, remote, peer, next_port, next_intent;
	struct intent local[INTENTS], foreign[INTENTS];
	struct command *commands, *command_last;
	unsigned command_count, outgoing_count;
	struct outgoing *outgoing, *outgoing_last;
	struct polaris_wifi_qrtr_port ports[PORTS];
	struct polaris_wifi_qrtr_server servers[SERVERS];
	bool present[SERVERS];
};
static struct polaris_wifi_glink *instances[INSTANCES];
static void pump(struct polaris_wifi_glink *);
static void progress(struct polaris_wifi_glink *);
static void qrtr_input(struct polaris_wifi_glink *, const uint8_t *, uint32_t);
static void drop_servers(struct polaris_wifi_glink *, uint32_t);
static bool pending(struct polaris_wifi_glink *);

static uint32_t
get32(const void *v)
{
	const uint8_t *p = v;
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t
get16(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8;
}

static void
put32(uint8_t *p, uint32_t n)
{
	p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8);
	p[2] = (uint8_t)(n >> 16); p[3] = (uint8_t)(n >> 24);
}

static void
header(uint8_t *p, unsigned cmd, uint32_t cid, uint32_t arg)
{
	p[0] = (uint8_t)cmd; p[1] = 0;
	p[2] = (uint8_t)cid; p[3] = (uint8_t)(cid >> 8);
	put32(p + 4, arg);
}

/* Bounded try gate: no waiting for another worker; callback recursion <= 4. */
static bool
enter(struct polaris_wifi_glink *g)
{
	uintptr_t me = PWF_THREAD_ID(), empty = 0;
	if (!me) return false;
	if (__atomic_load_n(&g->owner, __ATOMIC_ACQUIRE) == me) {
		if (g->depth == 4) return false;
		g->depth++;
		return true;
	}
	if (!__atomic_compare_exchange_n(&g->owner, &empty, me, false,
	    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return false;
	g->depth = 1;
	return true;
}

static void
leave(struct polaris_wifi_glink *g)
{
	if (--g->depth == 0)
		__atomic_store_n(&g->owner, 0, __ATOMIC_RELEASE);
}

static void
fault(struct polaris_wifi_glink *g, uint32_t error, uint32_t detail, bool uncertain)
{
	if (!g->first_error) { g->first_error = error; g->detail = detail; }
	g->broken = true;
	g->uncertain |= uncertain;
}

static void
broken(struct polaris_wifi_glink *g, const char *why)
{
	if (!g->broken) LOG(g, "polaris-wifi: GLINK error: %s\n", why);
	fault(g, PWF_PROTOCOL, 0, false);
}

static bool
scope(struct polaris_wifi_glink *g)
{
	if (g->broken) return false;
	if (!g->cfg.scope(g->cfg.ctx, g->cfg.epoch, &g->cfg.layout)) {
		fault(g, PWF_SCOPE, 0, g->started); return false;
	}
	return true;
}

static bool
order(struct polaris_wifi_glink *g)
{
	if (!scope(g)) return false;
	__sync_synchronize();
	if (!g->cfg.order(g->cfg.ctx)) { fault(g, PWF_ORDER, 0, g->started); return false; }
	return true;
}

static bool
inside(uint32_t at, uint32_t n, uint32_t base, uint32_t size)
{
	return at >= base && at - base <= size && n <= size - (at - base);
}

static bool
read_bytes(struct polaris_wifi_glink *g, uint32_t at, void *dst, uint32_t n)
{
	bool rx = inside(at, n, g->rx, g->rx_size);
	if (!n || (!rx && !inside(at, n, g->desc, 32)) || !scope(g)) {
		memset(dst, 0, n); if (!g->broken) fault(g, PWF_BOUNDS, at, false); return false;
	}
	/* Original Polaris RX allocation is cached-first; invalidate before reading. */
	if (rx && g->cfg.layout.rx.cached) {
		g->cache_ops++;
		if (!g->cfg.invalidate(g->cfg.ctx, at, n) || !order(g)) {
			memset(dst, 0, n); if (!g->broken) fault(g, PWF_CACHE, at, false); return false;
		}
	}
	g->reads++;
	if (!g->cfg.smem_read(g->cfg.ctx, at, dst, n) || !order(g)) {
		memset(dst, 0, n); if (!g->broken) fault(g, PWF_READ, at, false); return false;
	}
	return true;
}

static bool
word(struct polaris_wifi_glink *g, uint32_t at, uint32_t *out)
{
	uint8_t p[4];
	if (!read_bytes(g, at, p, 4)) return false;
	*out = get32(p); return true;
}

static bool
write_word(struct polaris_wifi_glink *g, uint32_t at, uint32_t value)
{
	/* Only APPS TX producer, RX consumer, or existing uncached TX data. */
	if ((at & 3) || (at != g->desc + 4 && at != g->desc + 8 &&
	    !inside(at, 4, g->tx, g->tx_size))) {
		fault(g, PWF_BOUNDS, at, false); return false;
	}
	if (!order(g)) return false;
	g->writes++; g->started = true;
	if (!g->cfg.smem_write32(g->cfg.ctx, at, value)) {
		fault(g, PWF_WRITE, at, true); return false;
	}
	if (!order(g)) { g->uncertain = true; return false; }
	return true;
}

static bool
ring(struct polaris_wifi_glink *g)
{
	if (!order(g)) return false;
	g->rings++;
	if (!g->cfg.ring(g->cfg.ctx)) { fault(g, PWF_RING, 0, true); return false; }
	return true;
}

static bool
marks(struct polaris_wifi_glink *g, bool tx, uint32_t *head, uint32_t *tail)
{
	uint32_t d = g->desc + (tx ? 0 : 8), size = tx ? g->tx_size : g->rx_size;
	if (!word(g, d + 4, head) || !word(g, d, tail)) return false;
	if (*head >= size || *tail >= size || ((*head | *tail) & 7)) {
		broken(g, "invalid FIFO marks"); return false;
	}
	return true;
}

static uint32_t
room(struct polaris_wifi_glink *g, bool reserve)
{
	uint32_t h, t, n, keep = reserve ? RESERVE : 8;
	if (!marks(g, true, &h, &t))
		return 0;
	n = t <= h ? g->tx_size - h + t : t - h;
	return n > keep ? n - keep : 0;
}

static bool
peek(struct polaris_wifi_glink *g, uint32_t tail, uint32_t offset, void *dst, uint32_t n)
{
	uint32_t at = (tail + offset) % g->rx_size, first = g->rx_size - at;
	if (first > n) first = n;
	if (!read_bytes(g, g->rx + at, dst, first)) return false;
	return first == n || read_bytes(g, g->rx, (uint8_t *)dst + first, n - first);
}

static bool
emit(struct polaris_wifi_glink *g, const uint8_t *h, uint32_t hn, const uint8_t *p, uint32_t pn, bool reserve)
{
	uint32_t head, tail, n = hn + pn, padded = (n + 7) & ~7u, i;
	if (!g->up || g->broken || room(g, reserve) < padded || !marks(g, true, &head, &tail))
		return false;
	for (i = 0; i < padded; i += 4) {
		uint8_t b[4];
		unsigned j;
		for (j = 0; j < 4; j++) {
			uint32_t k = i + j;
			b[j] = k < hn ? h[k] : k < n ? p[k - hn] : 0;
		}
		if (!write_word(g, g->tx + (head + i) % g->tx_size, get32(b))) return false;
	}
	if (!write_word(g, g->desc + 4, (head + padded) % g->tx_size)) return false;
	return ring(g);
}

static void
notify(struct polaris_wifi_glink *g)
{
	uint8_t b[8];
	uint32_t tail;
	if (!word(g, g->desc, &tail)) return;
	if (g->notified && tail == g->notify_tail) return;
	header(b, READ_NOTIFY, 0, 0);
	if (emit(g, b, 8, NULL, 0, false)) {
		g->notified = true;
		g->notify_tail = tail;
	}
}

static void
flush(struct polaris_wifi_glink *g)
{
	struct command *c;
	while ((c = g->commands) != NULL && !g->broken) {
		if (!emit(g, c->bytes, c->length, NULL, 0, true)) {
			notify(g);
			break;
		}
		g->commands = c->next;
		if (!g->commands) g->command_last = NULL;
		g->command_count--;
		PWF_FREE(c, sizeof(*c));
	}
}

static bool
say(struct polaris_wifi_glink *g, unsigned cmd, uint32_t cid, uint32_t arg, const void *p, uint32_t n)
{
	struct command *c;
	if (g->broken) return false;
	if (n > 40 || g->command_count == 256 || !(c = PWF_ALLOC(sizeof(*c)))) {
		broken(g, "control queue exhausted");
		return false;
	}
	memset(c, 0, sizeof(*c));
	header(c->bytes, cmd, cid, arg);
	if (n) memcpy(c->bytes + 8, p, n);
	c->length = 8 + n;
	if (g->command_last) g->command_last->next = c;
	else g->commands = c;
	g->command_last = c;
	g->command_count++;
	flush(g);
	return !g->broken;
}

static bool
offer(struct polaris_wifi_glink *g, uint32_t size, bool reusable)
{
	unsigned i;
	uint8_t pair[8];
	for (i = 0; i < INTENTS; i++) if (!g->local[i].there) break;
	if (i == INTENTS || !size || size > MAX_PACKET || g->next_intent == UINT32_MAX) return false;
	g->local[i].data = PWF_ALLOC(size);
	if (!g->local[i].data) return false;
	g->local[i].there = true;
	g->local[i].size = size;
	g->local[i].id = ++g->next_intent;
	g->local[i].reusable = reusable;
	put32(pair, size); put32(pair + 4, g->local[i].id);
	return say(g, INTENT, 1, 1, pair, 8);
}

static bool
clock_us(struct polaris_wifi_glink *g, uint64_t *out)
{
    uint64_t now = g->cfg.now_us(g->cfg.ctx);
    if (now < g->last_us) { fault(g, PWF_CLOCK, 0, g->started); return false; }
    g->last_us = now; *out = now; return true;
}

static struct outgoing *
queue_packet(struct polaris_wifi_glink *g, uint32_t type, uint32_t from, uint32_t node, uint32_t port,
    const void *p, uint32_t n, bool synchronous)
{
	uint32_t len = 32 + ((n + 3) & ~3u);
	uint64_t now;
	struct outgoing *o;
	if (!clock_us(g, &now)) return NULL;
	if (g->outgoing_count == 64 || !(o = PWF_ALLOC(sizeof(*o) + len))) return NULL;
	memset(o, 0, sizeof(*o) + len);
	o->length = len;
	o->synchronous = synchronous;
	o->since = now;
	put32(o->bytes, 1); put32(o->bytes + 4, type);
	put32(o->bytes + 8, g->cfg.local_node); put32(o->bytes + 12, from);
	put32(o->bytes + 20, n); put32(o->bytes + 24, node); put32(o->bytes + 28, port);
	if (n) memcpy(o->bytes + 32, p, n);
	if (g->outgoing_last) g->outgoing_last->next = o;
	else g->outgoing = o;
	g->outgoing_last = o;
	g->outgoing_count++;
	return o;
}

static void
control(struct polaris_wifi_glink *g, uint32_t type, uint32_t from, uint32_t node, uint32_t port,
    uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	uint8_t p[20];
	put32(p, type); put32(p + 4, a); put32(p + 8, b); put32(p + 12, c); put32(p + 16, d);
	if (!queue_packet(g, type, from, node, port, p, 20, false)) broken(g, "QRTR control queue exhausted");
}

static void
publish_notice(struct polaris_wifi_glink *g, struct polaris_wifi_qrtr_port *p, uint32_t type, uint32_t node, uint32_t port)
{
	uint8_t body[20];
	put32(body, type); put32(body + 4, p->service);
	put32(body + 8, p->version | p->instance << 8);
	put32(body + 12, g->cfg.local_node); put32(body + 16, p->id);
	if (!queue_packet(g, port == CTRL ? type : Q_DATA, CTRL, node, port, body, 20, false))
		broken(g, "local service announcement queue exhausted");
}

static void
finish(struct polaris_wifi_glink *g, int error)
{
	struct outgoing *o = g->outgoing;
	unsigned i;
	if (error && !g->uncertain && !o->offset && o->has_intent) for (i = 0; i < INTENTS; i++)
		if (g->foreign[i].there && g->foreign[i].id == o->iid) g->foreign[i].busy = false;
	if (error && o->length > 1000) LOG(g, "polaris-wifi: send of %u bytes FAILED (%d), offset %u, intent %u\n", o->length, error, o->offset, o->iid);
	g->outgoing = o->next;
	if (!g->outgoing) g->outgoing_last = NULL;
	g->outgoing_count--;
	o->done = true; o->error = error;
	if (!o->synchronous) {
		if (error) LOG(g, "polaris-wifi: GLINK error: QRTR control send errno %d\n", error);
		PWF_FREE(o, sizeof(*o) + o->length);
	}
}

static void
progress(struct polaris_wifi_glink *g)
{
	struct outgoing *o;
	unsigned budget = 128;
	flush(g);
	while (budget-- && (o = g->outgoing) != NULL) {
		uint32_t n, available;
		uint8_t h[16];
		int best = -1;
		unsigned i;
		if (!g->up || g->broken) {
			finish(g, ENOTCONN);
			continue;
		}
		uint64_t now;
		if (!clock_us(g, &now)) { finish(g, EIO); continue; }
		if (now - o->since >= WAIT_US) {
			if (o->offset) broken(g, "partial transmit timed out");
			finish(g, ETIMEDOUT);
			continue;
		}
		if (!g->opened || g->commands) return;
		if (!o->has_intent) {
			for (i = 0; i < INTENTS; i++) {
				struct intent *v = &g->foreign[i];
				if (v->there && !v->busy && v->size >= o->length &&
				    (best < 0 || v->size < g->foreign[best].size)) best = (int)i;
			}
			if (best < 0) {
				if (o->answered && !o->granted) { finish(g, ENOBUFS); continue; }
				if (!o->requested) {
					o->requested = true;
					if (o->length > 1000) LOG(g, "polaris-wifi: no remote intent for %u bytes: asks for one\n", o->length);
					say(g, INTENT_REQ, 1, o->length, NULL, 0);
				}
				return;
			}
			g->foreign[best].busy = true;
			o->iid = g->foreign[best].id; o->has_intent = true;
			if (o->length > 1000) LOG(g, "polaris-wifi: sends %u bytes in remote intent %u (size %u)\n", o->length, o->iid, g->foreign[best].size);
		}
		available = room(g, true);
		if (available < 24) { notify(g); return; }
		n = o->length - o->offset;
		if (n > 8192) n = 8192;
		if (n > available - 16) n = (available - 16) & ~7u;
		header(h, o->offset ? DATA_MORE : DATA, 1, o->iid);
		put32(h + 8, n); put32(h + 12, o->length - o->offset - n);
		if (!emit(g, h, 16, o->bytes + o->offset, n, true)) return;
		o->offset += n;
		if (o->offset == o->length) finish(g, 0);
	}
}

static bool
matches(const struct lookup *l, const struct polaris_wifi_qrtr_server *s)
{
	return l->used && (!l->service || l->service == s->service) &&
	    ((!l->version && !l->instance) || (l->version == s->version && l->instance == s->instance));
}

static void
announce(struct polaris_wifi_glink *g, bool arrived, struct polaris_wifi_qrtr_server s)
{
	unsigned i, j;
	for (i = 0; i < PORTS; i++) {
		struct polaris_wifi_qrtr_port *p = &g->ports[i];
		if (!p->live || !p->server) continue;
		for (j = 0; j < LOOKUPS; j++) {
			if (matches(&p->lookups[j], &s)) {
				p->server(p->ctx, arrived, s.service, s.version, s.instance, s.node, s.port);
				break;
			}
		}
	}
}

static void
drop_servers(struct polaris_wifi_glink *g, uint32_t node)
{
	unsigned i;
	for (i = 0; i < SERVERS; i++) if (g->present[i] && (node == BCAST || g->servers[i].node == node)) {
		struct polaris_wifi_qrtr_server s = g->servers[i];
		g->present[i] = false;
		announce(g, false, s);
	}
}

static void
qrtr_input(struct polaris_wifi_glink *g, const uint8_t *p, uint32_t len)
{
	uint32_t type, sn, sp, dn, dp, confirm, size, at, command;
	unsigned i;
	if (len < 16 || (len & 3)) goto bad;
	if (p[0] == 1) {
		if (len < 32 || get32(p) != 1) goto bad;
		type = get32(p + 4); sn = get32(p + 8); sp = get32(p + 12);
		confirm = get32(p + 16); size = get32(p + 20);
		dn = get32(p + 24); dp = get32(p + 28); at = 32;
	} else if (p[0] == 3) {
		type = p[1]; confirm = p[2] & 1; at = 16u + p[3]; size = get32(p + 4);
		sn = get16(p + 8); sp = get16(p + 10); dn = get16(p + 12); dp = get16(p + 14);
		if (sp == 0xfffe) sp = CTRL;
		if (dp == 0xfffe) dp = CTRL;
	} else goto bad;
	if (dp == 0xffff) dp = CTRL;
	if (at > len || !size || size > len - at || ((size + 3) & ~3u) != len - at) goto bad;
	if ((dn != g->cfg.local_node && dn != BCAST) || sn == g->cfg.local_node || sn == BCAST) goto bad;
	if (dp != CTRL && type != Q_DATA && type != Q_RESUME) goto bad;
	if (type == Q_RESUME) return;
	if (confirm) control(g, Q_RESUME, dp, sn, sp, dn, dp, 0, 0);
	if (g->broken) return;
	/* Nameserver answers a NEW_LOOKUP to the requesting local port, using
	 * Q_DATA. Only a port with an exact matching live lookup may route that
	 * 20-byte control message into service discovery, never arbitrary data. */
	bool lookup_reply = false;
	if (dp != CTRL && type == Q_DATA && size == 20 &&
	    (get32(p + at) == Q_NEW_SERVER || get32(p + at) == Q_DEL_SERVER)) {
		struct polaris_wifi_qrtr_server candidate = {
			get32(p + at + 4), get32(p + at + 8) & 255, get32(p + at + 8) >> 8,
			get32(p + at + 12), get32(p + at + 16)};
		for (i = 0; i < PORTS; i++) if (g->ports[i].live && g->ports[i].id == dp)
			for (unsigned j = 0; j < LOOKUPS; j++)
				if (matches(&g->ports[i].lookups[j], &candidate)) lookup_reply = true;
	}
	if (dp != CTRL && type == Q_DATA && !lookup_reply) {
		for (i = 0; i < PORTS; i++) {
			struct polaris_wifi_qrtr_port *port = &g->ports[i];
			if (port->live && port->id == dp && port->receive) {
				port->receive(port->ctx, sn, sp, p + at, size);
				break;
			}
		}
		return;
	}
	if (size < 20) goto bad;
	p += at;
	command = get32(p);
	if (type != Q_DATA && command != type) goto bad;
	switch (command) {
	case Q_HELLO:
		if (!g->hello) {
			g->hello = true; g->peer = sn;
			control(g, Q_HELLO, CTRL, sn, CTRL, 0, 0, 0, 0);
			LOG(g, "polaris-wifi: qrtr hello from node %u\n", sn);
		}
		for (i = 0; i < PORTS; i++) if (g->ports[i].live && g->ports[i].published)
			publish_notice(g, &g->ports[i], Q_NEW_SERVER, sn, CTRL);
		break;
	case Q_BYE:
		drop_servers(g, sn);
		if (g->peer == sn) { g->hello = false; g->peer = 0; }
		break;
	case Q_NEW_SERVER:
	case Q_DEL_SERVER: {
		struct polaris_wifi_qrtr_server s;
		int found = -1, empty = -1;
		uint32_t packed = get32(p + 8);
		s.service = get32(p + 4); s.version = packed & 255; s.instance = packed >> 8;
		s.node = get32(p + 12); s.port = get32(p + 16);
		if (!s.service || s.node == g->cfg.local_node || s.node == BCAST || !s.port || s.port >= CTRL) break;
		for (i = 0; i < SERVERS; i++) {
			if (!g->present[i]) { if (empty < 0) empty = (int)i; continue; }
			if (g->servers[i].node == s.node && g->servers[i].port == s.port) { found = (int)i; break; }
		}
		if (found >= 0) {
			struct polaris_wifi_qrtr_server old = g->servers[found];
			bool same = old.service == s.service && old.version == s.version && old.instance == s.instance;
			if (command == Q_NEW_SERVER && same) break;
			if (command == Q_DEL_SERVER && !same) break;
			g->present[found] = false;
			announce(g, false, old);
		} else if (command == Q_DEL_SERVER) break;
		if (command == Q_NEW_SERVER) {
			if (found < 0) found = empty;
			if (found < 0) { broken(g, "server table exhausted"); break; }
			g->servers[found] = s; g->present[found] = true;
			LOG(g, "polaris-wifi: qrtr server: service %u version %u instance %u node %u port %u\n",
			    s.service, s.version, s.instance, s.node, s.port);
			announce(g, true, s);
		}
		break;
	}
	case Q_NEW_LOOKUP:
		for (i = 0; i < PORTS; i++) {
			struct polaris_wifi_qrtr_port *port = &g->ports[i];
			uint32_t service = get32(p + 4), packed = get32(p + 8);
			if (port->live && port->published && (!service || service == port->service) &&
			    (!packed || packed == (port->version | port->instance << 8)))
				publish_notice(g, port, Q_NEW_SERVER, sn, sp);
		}
		{
			uint8_t end[20] = { 0 };
			put32(end, Q_NEW_SERVER);
			if (!queue_packet(g, sp == CTRL ? Q_NEW_SERVER : Q_DATA, CTRL, sn, sp, end, 20, false))
				broken(g, "local lookup terminator queue exhausted");
		}
		break;
	case Q_DEL_LOOKUP:
		/* Remote lookups are snapshots; no remote subscription survives a request. */
		break;
	case Q_DEL_CLIENT:
		for (i = 0; i < SERVERS; i++) if (g->present[i] && g->servers[i].node == get32(p + 4) &&
		    g->servers[i].port == get32(p + 8)) {
			struct polaris_wifi_qrtr_server s = g->servers[i];
			g->present[i] = false; announce(g, false, s);
		}
		break;
	default:
		break;
	}
	return;
bad:
	LOG(g, "polaris-wifi: GLINK error: malformed QRTR packet dropped\n");
}

static void
clear_intents(struct polaris_wifi_glink *g)
{
	unsigned i;
	for (i = 0; i < INTENTS; i++) {
		if (g->local[i].data) PWF_FREE(g->local[i].data, g->local[i].size);
	}
	memset(g->local, 0, sizeof(g->local));
	memset(g->foreign, 0, sizeof(g->foreign));
}

static void
open_channel(struct polaris_wifi_glink *g)
{
	static const uint32_t sizes[10] = { 0x800, 0x800, 0x800, 0x800, 0x800, 0x2000, 0x2000, 0x2000, 0x4400, 0x4400 };
	unsigned i;
	if (!g->agreed || !g->remote || g->closing || g->stop_requested) return;
	if (!g->asked) {
		g->asked = true;
		say(g, OPEN, 1, 7, "IPCRTR", 7);
	}
	if (!g->acked || g->opened) return;
	g->opened = true;
	LOG(g, "polaris-wifi: IPCRTR open both ways\n");
	for (i = 0; i < 10; i++) if (!offer(g, sizes[i], true)) {
		broken(g, "initial intent allocation failed");
		break;
	}
}

static void
pump(struct polaris_wifi_glink *g)
{
	unsigned budget = 256;
	while (budget-- && g->up && !g->broken) {
		uint8_t h[16], extra[40];
		uint32_t head, tail, avail, cmd, cid, arg, n = 8, chunk = 0, left = 0;
		unsigned i;
		if (!marks(g, false, &head, &tail)) return;
		avail = head >= tail ? head - tail : g->rx_size - tail + head;
		if (avail < 8) return;
		if (!peek(g, tail, 0, h, 8)) return;
		cmd = get16(h); cid = get16(h + 2); arg = get32(h + 4);
		if (cmd == OPEN) {
			n += arg & 0xffff;
			if (!(arg & 0xffff) || (arg & 0xffff) > 32) { broken(g, "bad channel name length"); return; }
		} else if (cmd == INTENT) {
			if (arg > (g->rx_size - 16) / 8) { broken(g, "bad intent count"); return; }
			n += 8 * arg;
		} else if (cmd == DATA || cmd == DATA_MORE) {
			if (avail < 16) return;
			if (!peek(g, tail, 8, h + 8, 8)) return;
			chunk = get32(h + 8); left = get32(h + 12);
			if (chunk > g->rx_size - 24) { broken(g, "oversized fragment"); return; }
			n = 16 + chunk;
		}
		n = (n + 7) & ~7u;
		if (n > g->rx_size - 8) { broken(g, "oversized frame"); return; }
		if (avail < n) return;
		if (cmd == OPEN) {
			memset(extra, 0, sizeof(extra));
			if (!peek(g, tail, 8, extra, arg & 0xffff)) return;
			if (extra[(arg & 0xffff) - 1] != 0 || !cid) { broken(g, "bad channel name or id"); return; }
		}
		if (cmd == INTENT && cid == g->remote) {
			for (i = 0; i < arg; i++) {
				uint32_t size, id;
				unsigned j;
				if (!peek(g, tail, 8 + 8 * i, extra, 8)) return;
				size = get32(extra); id = get32(extra + 4);
				/* Linux does not refuse these: the modem's firmware numbers its intents from 0; a zero size is of no use, skip it */
				LOG(g, "polaris-wifi: remote intent id %u size %u (%s)\n", id, size, "own-SMEM");
				if (!size) continue;
				for (j = 0; j < INTENTS; j++) if (g->foreign[j].there && g->foreign[j].id == id) break;
				if (j < INTENTS) {
					if (g->foreign[j].busy || g->foreign[j].size != size) { broken(g, "conflicting remote intent"); return; }
					continue;
				}
				for (j = 0; j < INTENTS; j++) if (!g->foreign[j].there) break;
				if (j == INTENTS) { broken(g, "remote intent table exhausted"); return; }
				g->foreign[j].there = true; g->foreign[j].id = id; g->foreign[j].size = size;
			}
		}
		if ((cmd == DATA || cmd == DATA_MORE) && cid == g->remote && g->opened) {
			struct intent *v = NULL;
			uint8_t *packet = NULL;
			uint32_t total = 0;
			for (i = 0; i < INTENTS; i++) if (g->local[i].there && g->local[i].id == arg) { v = &g->local[i]; break; }
			if (!v || !chunk || chunk > v->size - v->fill || left > v->size - v->fill - chunk ||
			    (cmd == DATA && v->busy) || (cmd == DATA_MORE && (!v->busy || v->left != chunk + left))) {
				broken(g, "invalid fragment sequence or intent"); return;
			}
			if (!peek(g, tail, 16, v->data + v->fill, chunk)) return;
			v->fill += chunk; v->left = left; v->busy = left != 0;
			if (!left) {
				total = v->fill;
				packet = PWF_ALLOC(total);
				if (!packet) { broken(g, "receive allocation failed"); return; }
				memcpy(packet, v->data, total);
				v->fill = 0;
			}
			if (!write_word(g, g->desc + 8, (tail + n) % g->rx_size)) {
				if (packet) PWF_FREE(packet, total); return;
			}
			if (!left) {
				say(g, v->reusable ? DONE_REUSE : DONE, 1, arg, NULL, 0);
				if (!v->reusable) {
					PWF_FREE(v->data, v->size); memset(v, 0, sizeof(*v));
				}
				if (!g->broken) qrtr_input(g, packet, total);
				PWF_FREE(packet, total);
			}
			continue;
		}
		if (!write_word(g, g->desc + 8, (tail + n) % g->rx_size)) return;
		switch (cmd) {
		case VERSION:
			if (!cid) { broken(g, "remote has no version"); break; }
			if (cid == 1) g->features &= arg;
			say(g, VERSION_ACK, 1, g->features, NULL, 0);
			break;
		case VERSION_ACK:
			if (!cid) { broken(g, "version negotiation rejected"); break; }
			if (cid == 1 && arg == g->features) g->agreed = true;
			else { g->features &= arg; say(g, VERSION, 1, g->features, NULL, 0); }
			break;
		case OPEN:
			say(g, OPEN_ACK, cid, 0, NULL, 0);
			if ((arg & 0xffff) == 7 && !memcmp(extra, "IPCRTR", 7)) {
				if (g->remote && g->remote != cid) { broken(g, "IPCRTR channel changed without close"); break; }
				g->remote = cid;
			} else LOG(g, "polaris-wifi: unsupported remote channel %u %s: acknowledged, data ignored\n", cid, extra);
			break;
		case OPEN_ACK:
			if (cid == 1 && g->asked && !g->closing) g->acked = true;
			break;
		case INTENT: break;
		case INTENT_REQ:
			if (cid == g->remote && g->opened) {
				bool granted = offer(g, arg, false);
				say(g, INTENT_ACK, 1, granted ? 1 : 0, NULL, 0);
			}
			break;
		case INTENT_ACK:
			if (cid == g->remote && g->outgoing && g->outgoing->requested) {
				g->outgoing->answered = true; g->outgoing->granted = arg != 0;
				if (g->outgoing->length > 1000) LOG(g, "polaris-wifi: the modem %s the intent request for %u bytes\n", arg ? "grants" : "REFUSES", g->outgoing->length);
			}
			break;
		case DONE:
		case DONE_REUSE:
			if (cid == g->remote) for (i = 0; i < INTENTS; i++) if (g->foreign[i].there && g->foreign[i].id == arg) {
				/* The modem can answer before emit() has returned and offset has been counted: not an error. */
				if (g->foreign[i].size > 1000) LOG(g, "polaris-wifi: remote done with intent %u (size %u), %s\n", arg, g->foreign[i].size, cmd == DONE_REUSE ? "reusable" : "gone");
				g->foreign[i].busy = false;
				g->foreign[i].there = cmd == DONE_REUSE;
				break;
			}
			break;
		case READ_NOTIFY:
			(void)ring(g);
			break;
		case CLOSE:
			if (cid == g->remote && pending(g)) {
				fault(g, PWF_PROTOCOL, CLOSE, true); break;
			}
			say(g, CLOSE_ACK, cid, 0, NULL, 0);
			if (cid == g->remote) {
				g->remote = 0; g->opened = false; g->hello = false;
				if (g->asked && !g->closing) { g->closing = true; say(g, CLOSE, 1, 0, NULL, 0); }
				while (g->outgoing) finish(g, ENOTCONN);
				clear_intents(g); drop_servers(g, BCAST);
			}
			break;
		case CLOSE_ACK:
			if (cid == 1 && g->closing) { g->closing = false; g->asked = false; g->acked = false; g->close_confirmed = true; }
			break;
		case DATA:
		case DATA_MORE:
		case SIGNALS:
			break;
		default: broken(g, "unknown command"); break;
		}
		open_channel(g);
	}
}

static struct polaris_wifi_qrtr_port *
open_slot(unsigned slot, polaris_wifi_qrtr_receive_t receive, polaris_wifi_qrtr_server_t server, void *ctx)
{
	struct polaris_wifi_glink *g = __atomic_load_n(&instances[slot], __ATOMIC_ACQUIRE);
	struct polaris_wifi_qrtr_port *p = NULL;
	unsigned i;
	if (!g) return NULL;
	if (!enter(g)) return NULL;
	if (g->up && !g->stop_requested && !g->broken && g->next_port < 0xfffd) for (i = 0; i < PORTS; i++) if (!g->ports[i].live) {
		p = &g->ports[i];
		memset(p->lookups, 0, sizeof(p->lookups));
		p->g = g; p->id = ++g->next_port; p->generation++;
		p->receive = receive; p->server = server; p->ctx = ctx; p->live = true;
		p->published = false;
		break;
	}
	leave(g);
	return p;
}

static int
send_port(struct polaris_wifi_qrtr_port *p, uint32_t node, uint32_t port, const void *data, size_t length)
{
	struct polaris_wifi_glink *g;
	struct outgoing *o;
	int error;
	if (!p || (!data && length) || !length) return EINVAL;
	if (length > POLARIS_WIFI_GLINK_MAX_DATAGRAM) return EMSGSIZE;
	g = p->g; if (!enter(g)) return EBUSY;
	if (!p->live || !g->up || !g->opened || g->stop_requested || g->broken) { leave(g); return ENOTCONN; }
	if (node == g->cfg.local_node || node == BCAST || !port || port >= CTRL) { leave(g); return EINVAL; }
	o = queue_packet(g, Q_DATA, p->id, node, port, data, (uint32_t)length, true);
	if (!o) { leave(g); return ENOMEM; }
	/* Also bound iterations if the platform clock/sleep is frozen. */
	for (unsigned budget = WAIT_US / 1000u + 1; !o->done && budget; budget--) {
		pump(g); progress(g);
		if (!o->done) g->cfg.sleep_us(g->cfg.ctx, 1000);
	}
	if (!o->done) {
		fault(g, PWF_CLOCK, 0, o->offset != 0);
		while (g->outgoing) finish(g, ETIMEDOUT);
	}
	error = g->broken ? EIO : o->error;
	PWF_FREE(o, sizeof(*o) + o->length);
	leave(g);
	return error;
}

static int
lookup_port(struct polaris_wifi_qrtr_port *p, uint32_t service, uint32_t version, uint32_t instance)
{
	struct polaris_wifi_glink *g;
	struct lookup *l = NULL;
	struct polaris_wifi_qrtr_server snapshot[SERVERS];
	unsigned i, count = 0;
	uint32_t generation;
	if (!p || version > 255 || instance > 0xffffff) return EINVAL;
	g = p->g; if (!enter(g)) return EBUSY;
	if (!p->live || !g->up || g->broken) { leave(g); return ENOTCONN; }
	for (i = 0; i < LOOKUPS; i++) {
		if (!p->lookups[i].used) { if (!l) l = &p->lookups[i]; continue; }
		if (p->lookups[i].service == service && p->lookups[i].version == version && p->lookups[i].instance == instance) {
			leave(g); return 0;
		}
	}
	if (!l) { leave(g); return ENOSPC; }
	l->used = true; l->service = service; l->version = version; l->instance = instance;
	generation = p->generation;
	for (i = 0; i < SERVERS; i++) if (g->present[i] && matches(l, &g->servers[i])) snapshot[count++] = g->servers[i];
	for (i = 0; i < count && p->live && p->generation == generation && p->server; i++) {
		struct polaris_wifi_qrtr_server s = snapshot[i];
		p->server(p->ctx, true, s.service, s.version, s.instance, s.node, s.port);
	}
	if (p->live && p->generation == generation && !g->stop_requested) {
		control(g, Q_NEW_LOOKUP, p->id, g->hello ? g->peer : BCAST, CTRL,
		    service, version | instance << 8, g->cfg.local_node, p->id);
		progress(g);
	}
	int error = g->broken ? EIO : 0;
	leave(g);
	return error;
}

int
polaris_wifi_glink_close_port(struct polaris_wifi_qrtr_port *p)
{
	struct polaris_wifi_glink *g;
	if (!p) return EINVAL;
	g = p->g; if (!enter(g)) return EBUSY;
	if (p->live) {
		if (p->published && g->up && g->opened && g->hello && !g->broken)
			publish_notice(g, p, Q_DEL_SERVER, g->peer, CTRL);
		p->published = false;
		p->live = false; p->generation++;
		memset(p->lookups, 0, sizeof(p->lookups));
		if (g->up && g->opened && !g->broken)
			control(g, Q_DEL_CLIENT, p->id, (g->hello || g->peer) ? g->peer : BCAST, CTRL, g->cfg.local_node, p->id, 0, 0);
		progress(g);
	}
	leave(g); return 0;
}

static void
close_port(struct polaris_wifi_qrtr_port *p)
{
    (void)polaris_wifi_glink_close_port(p);
}

#define SLOT(n) static struct polaris_wifi_qrtr_port *open_##n(polaris_wifi_qrtr_receive_t r, polaris_wifi_qrtr_server_t s, void *c) \
	{ return open_slot(n, r, s, c); }
SLOT(0) SLOT(1) SLOT(2) SLOT(3) SLOT(4) SLOT(5) SLOT(6) SLOT(7)
#define OPS(n) { open_##n, send_port, lookup_port, close_port }
static const struct polaris_wifi_qrtr_ops all_ops[INSTANCES] = { OPS(0), OPS(1), OPS(2), OPS(3), OPS(4), OPS(5), OPS(6), OPS(7) };

struct polaris_wifi_glink *
polaris_wifi_glink_create(const struct polaris_wifi_glink_cfg *cfg)
{
	struct polaris_wifi_glink *g;
	unsigned i;
	if (!cfg || !cfg->epoch || !cfg->scope || !cfg->smem_read || !cfg->smem_write32 ||
	    !cfg->ring || !cfg->order || !cfg->invalidate || !cfg->sleep_us || !cfg->now_us ||
	    cfg->smem_phys != UINT64_C(0x86000000) || cfg->smem_bytes != 0x200000 ||
	    !cfg->layout.remote || cfg->layout.remote >= PSM_HOST_COUNT ||
	    cfg->layout.descriptor.cached || cfg->layout.tx.cached || cfg->layout.rx.cached > 1 ||
	    cfg->layout.descriptor.bytes != 32 || !cfg->layout.headers ||
	    cfg->layout.partition > cfg->smem_bytes ||
	    cfg->layout.partition_bytes > cfg->smem_bytes - cfg->layout.partition ||
	    cfg->layout.partition_bytes < 32 || !cfg->local_node || cfg->local_node >= CTRL)
		return NULL;
	const struct polaris_glink_item *items[3] = { &cfg->layout.descriptor, &cfg->layout.tx, &cfg->layout.rx };
	for (i = 0; i < 3; i++) {
		const struct polaris_glink_item *v = items[i];
		if ((v->offset & 7) || (v->bytes & 7) || !v->bytes ||
		    !inside(v->offset, v->bytes, cfg->layout.partition + 32, cfg->layout.partition_bytes - 32) ||
		    (i && v->bytes < 64)) return NULL;
		for (unsigned j = 0; j < i; j++)
			if (v->offset < items[j]->offset + items[j]->bytes && items[j]->offset < v->offset + v->bytes)
				return NULL;
	}
	/* Metadata is not permission: a native owner/mapping/MPU witness is required. */
	if (!cfg->scope(cfg->ctx, cfg->epoch, &cfg->layout)) return NULL;
	g = PWF_ALLOC(sizeof(*g));
	if (!g) return NULL;
	memset(g, 0, sizeof(*g)); g->cfg = *cfg;
	g->desc = cfg->layout.descriptor.offset; g->tx = cfg->layout.tx.offset;
	g->tx_size = cfg->layout.tx.bytes; g->rx = cfg->layout.rx.offset; g->rx_size = cfg->layout.rx.bytes;
	for (i = 0; i < INSTANCES; i++) {
		struct polaris_wifi_glink *empty = NULL;
		if (__atomic_compare_exchange_n(&instances[i], &empty, g, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
			g->slot = i; return g;
		}
	}
	PWF_FREE(g, sizeof(*g)); return NULL;
}

int
polaris_wifi_glink_start(struct polaris_wifi_glink *g)
{
	uint32_t th, tt, rh, rt;
	if (!g) return EINVAL;
	if (!enter(g)) return EBUSY;
	int error = 0;
	if (g->up || g->started || g->stop_requested) { error = EALREADY; goto out; }
	if (!scope(g) || !marks(g, true, &th, &tt) || !marks(g, false, &rh, &rt)) { error = EIO; goto out; }
	/* Never reset FIFO indices. An existing nonempty channel needs its previous
	 * owner/SSR protocol; no candidate may discard remote data to make room. */
	if (th != tt || rh != rt) { fault(g, PWF_PENDING, 0, false); error = EBUSY; goto out; }
	g->up = true; g->features = 1; g->next_port = 0x3fff;
	say(g, VERSION, 1, g->features, NULL, 0);
	if (g->broken) error = EIO;
out:
	leave(g); return error;
}

int
polaris_wifi_glink_poll_once(struct polaris_wifi_glink *g)
{
	if (!g) return EINVAL;
	if (!enter(g)) return EBUSY;
	if (g->up && scope(g)) { pump(g); progress(g); }
	int error = g->broken ? EIO : !g->up ? ENOTCONN : 0;
	leave(g); return error;
}

static bool
pending(struct polaris_wifi_glink *g)
{
	if (g->outgoing || g->commands) return true;
	for (unsigned i = 0; i < INTENTS; i++)
		if (g->foreign[i].busy || g->local[i].busy || g->local[i].fill) return true;
	return false;
}

int
polaris_wifi_glink_stop(struct polaris_wifi_glink *g)
{
	uint32_t th, tt, rh, rt;
	if (!g) return EINVAL;
	if (!enter(g)) return EBUSY;
	int error = 0;
	if (g->broken || !scope(g)) { error = EIO; goto out; }
	g->stop_requested = true;
	for (unsigned i = 0; i < PORTS; i++) if (g->ports[i].live) { error = EBUSY; goto out; }
	if (!g->up) goto out;
	pump(g); progress(g);
	if (g->broken) { error = EIO; goto out; }
	/* Do not CLOSE ahead of unresolved data/remote intents. Poll then retry
	 * stop only after real DONE; the lease is never silently released. */
	if (pending(g)) { error = EBUSY; goto out; }
	if (g->asked && !g->closing) { g->closing = true; say(g, CLOSE, 1, 0, NULL, 0); }
	if (g->asked || g->closing || g->broken || !marks(g, true, &th, &tt) || !marks(g, false, &rh, &rt)) {
		error = g->broken ? EIO : EBUSY; goto out;
	}
	if (th != tt || rh != rt || pending(g) || (g->started && !g->close_confirmed)) { error = EBUSY; goto out; }
	clear_intents(g); memset(g->present, 0, sizeof(g->present)); g->up = false;
out:
	leave(g); return error;
}

int
polaris_wifi_glink_status(struct polaris_wifi_glink *g, struct polaris_wifi_glink_status *out)
{
	if (!g || !out) return EINVAL;
	if (!enter(g)) return EBUSY;
	*out = (struct polaris_wifi_glink_status){
		g->cfg.epoch, g->first_error, g->detail, g->reads, g->writes, g->rings, g->cache_ops,
		g->up, g->opened, g->hello, g->stop_requested, g->uncertain, pending(g),
		/* This is transport quiescence only; never storage/native/DMA durableSAFE. */
		!g->up && !g->broken && !pending(g) && (!g->started || g->close_confirmed) };
	leave(g); return 0;
}

int
polaris_wifi_glink_destroy(struct polaris_wifi_glink *g)
{
	if (!g) return EINVAL;
	if (!enter(g)) return EBUSY;
	if (g->up || g->broken || pending(g) || (g->started && !g->close_confirmed)) { leave(g); return EBUSY; }
	for (unsigned i = 0; i < PORTS; i++) if (g->ports[i].live) { leave(g); return EBUSY; }
	/* Lifecycle callers must quiesce/discard all callbacks/handles first. */
	__atomic_store_n(&instances[g->slot], NULL, __ATOMIC_RELEASE);
	leave(g); PWF_FREE(g, sizeof(*g)); return 0;
}

const struct polaris_wifi_qrtr_ops *
polaris_wifi_glink_qrtr_ops(struct polaris_wifi_glink *g)
{
	return g ? &all_ops[g->slot] : NULL;
}

int
polaris_wifi_glink_qrtr_publish(struct polaris_wifi_glink *g, struct polaris_wifi_qrtr_port *p,
    uint32_t service, uint32_t version, uint32_t instance)
{
	int error = 0;
	if (!g || !p || p->g != g || !service || version > 255 || instance > 0xffffff) return EINVAL;
	if (!enter(g)) return EBUSY;
	if (!g->up || g->broken || !p->live) { error = ENOTCONN; goto out; }
	if (p->published && p->service == service && p->version == version && p->instance == instance) goto out;
	if (p->published && g->hello && g->opened) publish_notice(g, p, Q_DEL_SERVER, g->peer, CTRL);
	p->service = service; p->version = version; p->instance = instance; p->published = true;
	if (g->hello && g->opened) publish_notice(g, p, Q_NEW_SERVER, g->peer, CTRL);
	if (g->broken) error = EIO;
out:
	leave(g);
	return error;
}

int
polaris_wifi_glink_qrtr_servers(struct polaris_wifi_glink *g, struct polaris_wifi_qrtr_server *out, unsigned max)
{
	unsigned i, count = 0;
	if (!g || (!out && max)) return -EINVAL;
	if (!enter(g)) return -EBUSY;
	for (i = 0; i < SERVERS && count < max; i++) if (g->present[i]) out[count++] = g->servers[i];
	leave(g);
	return (int)count;
}
