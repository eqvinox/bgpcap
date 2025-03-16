// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * load .pcapng, reassemble TCP and split up into per-BGP-session files
 */

#include "config.h"
#include "compiler.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include <assert.h>
#include "xref.h"
#include "printfrr.h"
#include "zlog.h"
#include "typesafe.h"
#include "jhash.h"
#include "sockunion.h"

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#define DEBUG 0

/* pcapng on-disk formats
 *
 * would normally need __attribute__((packed)) but everything is nicely aligned
 */

struct blockhdr {
	uint32_t block_type;
	uint32_t block_len;
};

struct shb {
	struct blockhdr;

	uint32_t bo_magic;
	uint16_t major, minor;
	uint64_t section_len;
};

struct epb {
	struct blockhdr;

	uint32_t ifid;
	uint32_t ts_hi;
	uint32_t ts_lo;
	uint32_t cap_len;
	uint32_t orig_len;

	uint8_t pkt[0];
};

struct idb {
	struct blockhdr;
	uint16_t dlt, rsvd;
	uint32_t snaplen;
};

/* TCP segments */

PREDECL_DLIST(segs);

struct seg {
	struct segs_item item;
	const uint8_t *data;

	/* next 2 must be uint32_t to get proper wrapping math! */
	uint32_t len;
	uint32_t seq;

	uint64_t ts;
};

#if 0
/*
 * unfortunately this won't work due to sequence number wraparound.  the
 * code instead maintains the list order manually.
 */
static inline int segs_cmp(const struct seg *a, const struct seg *b)
{
	return numcmp(a->seq, b->seq);
}
#endif

DECLARE_DLIST(segs, struct seg, item); //, segs_cmp);

/* (unidirectional) conversation */

PREDECL_HASH(convs);

struct conv {
	struct convs_item item;

	struct peer *peer;
	uint16_t port_src, port_dst;

	/* fd = -2: not opened yet, will open when seeing data
	 * fd = -1: error on opening, don't try again
	 */
	int fd;
	FILE *ffd;

	bool syn_seen;
	uint32_t syn_seq;

	/* sequence number to continue processing BGP PDUs from */
	uint32_t expect;

	/* size of current BGP PDU if known (= more than 18 bytes buffered)
	 * technically uint16_t would suffice
	 */
	uint32_t nextmsg;

	/* TCP segments */
	struct segs_head segs[1];
};

static int conv_cmp(const struct conv *a, const struct conv *b)
{
	return
		numcmp((uintptr_t)a->peer, (uintptr_t)b->peer) ?:
		numcmp(a->port_src, b->port_src) ?:
		numcmp(a->port_dst, b->port_dst);
}

static uint32_t conv_hash(const struct conv *a)
{
	return jhash_3words((uintptr_t)a->peer, a->port_src, a->port_dst,
			    0xbeefcafe);
}

DECLARE_HASH(convs, struct conv, item, conv_cmp, conv_hash);

/* IP(v4|v6) endpoint
 *
 * local addresses are added with dirfd = -2
 */

PREDECL_HASH(peers);

struct peer {
	struct peers_item item;
	union sockunion addr;

	/* directory fd for use in openat() */
	int dirfd;
	/* pcapng with all traffic from or to this endpoint */
	int fd;

	struct convs_head convs[1];
};

static int peer_cmp(const struct peer *a, const struct peer *b)
{
	return sockunion_cmp(&a->addr, &b->addr);
}

static uint32_t peer_hash(const struct peer *a)
{
	return sockunion_hash(&a->addr);
}

DECLARE_HASH(peers, struct peer, item, peer_cmp, peer_hash);

/* get the next (sz) bytes from the TCP conversation
 * called only after checking that the number of bytes is in fact
 * available
 *
 * if(pop) remove segments/bytes from list and move conv->expect forward
 */
static uint64_t linearize(struct conv *c, uint8_t *out, size_t sz, bool pop)
{
	uint64_t ts = 0;
	struct seg *seg;

	seg = segs_first(c->segs);

	while (seg && sz) {
		size_t copy = MIN(sz, seg->len);

		ts = MAX(seg->ts, ts);
		memcpy(out, seg->data, copy);
		out += copy;
		sz -= copy;

		if (!pop) {
			seg = segs_next(c->segs, seg);
			continue;
		}
		
		c->expect += copy;
		seg->len -= copy;
		if (!seg->len) {
			free(segs_pop(c->segs));
			seg = segs_first(c->segs);
		} else {
			seg->seq += copy;
			seg->data += copy;
			break;
		}
	}

	assert(sz == 0);
	return ts;
}

/* process a single complete BGP PDU */
static inline void cwrite(struct conv *c, const void *p, size_t s)
{
	assert(fwrite(p, 1, s, c->ffd) == s);
}

static void handle_bgp(struct conv *c, const uint8_t *bbuf, size_t len, uint64_t ts)
{
	uint32_t block_len;

	if (c->fd == -2) {
		char namebuf[256];

		snprintfrr(namebuf, sizeof(namebuf), "stream_%u_%u.pcapng", c->port_src, c->port_dst);
		c->fd = openat(c->peer->dirfd, namebuf, O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (c->fd == -1) {
			printfrr("creat(%pSU/%pSE): %m\n", &c->peer->addr, namebuf);
			return;
		}

		c->ffd = fdopen(c->fd, "w");

		/* mandatory section header block */
		struct shb shb = {
			.block_type = 0x0a0d0d0a,
			.block_len = (block_len = sizeof(struct shb) + 4),
			.bo_magic = 0x1a2b3c4d,
			.major = 1,
			.minor = 0,
			.section_len = ~0ULL,
		};

		cwrite(c, &shb, sizeof(shb));
		cwrite(c, &block_len, sizeof(block_len));

		/* need at least one interface description block */
		struct idb idb = {
			.block_type = 0x1,
			.block_len = (block_len = sizeof(struct idb) + 4),
			.dlt = 147,
			.snaplen = 65536,
		};

		cwrite(c, &idb, sizeof(idb));
		cwrite(c, &block_len, sizeof(block_len));
	}

	if (c->fd == -1)
		return;

	/* enhanced packet block */
	struct epb epb = {
		.block_type = 6,
		.block_len = (block_len = sizeof(struct epb) + 4 + ((len + 3) & ~3U)),
		.ifid = 0,
		.ts_hi = ts >> 32,
		.ts_lo = ts & 0xffffffff,
		.cap_len = len,
		.orig_len = len,
	};

	uint8_t pad[3] = {};

	cwrite(c, &epb, sizeof(epb));
	cwrite(c, bbuf, len);
	if (len & 3)
		cwrite(c, pad, 4 - (len & 3));
	cwrite(c, &block_len, sizeof(block_len));
}

#if 0
#undef DEBUG
#define DEBUG (c->port_src == 50577)
#endif

static void handle_tcp(struct peer *peer, const struct tcphdr *tcp, const uint8_t *end, uint64_t ts)
{
	struct conv ref = {}, *c;
	bool syn = tcp->th_flags & TH_SYN;
	bool ack = tcp->th_flags & TH_ACK;
	bool special = tcp->th_flags & (TH_FIN | TH_RST | TH_URG);
	uint32_t seq = ntohl(tcp->seq);
	uint8_t *data;

	ref.peer = peer;
	ref.port_src = ntohs(tcp->th_sport);
	ref.port_dst = ntohs(tcp->th_dport);

	if (special)
		return;

	c = convs_find(peer->convs, &ref);
	if (!c) {
		c = calloc(1, sizeof(*c));
		*c = ref;
		c->fd = -2;
		segs_init(c->segs);
		convs_add(peer->convs, c);

		if (!syn) {
			printfrr("tcp %-39pSU (%u->%u): created on non-SYN\n",
				 &peer->addr, c->port_src, c->port_dst);
		} else {
			printfrr("tcp %-39pSU (%u->%u): created on %s\n",
				 &peer->addr, c->port_src, c->port_dst,
				 ack ? "SYN-ACK" : "SYN");
			c->syn_seq = seq;
			c->expect = seq + 1;
			c->syn_seen = true;
		}
	} else {
		if (syn && c->syn_seen && c->syn_seq != seq) {
			printfrr("tcp %-39pSU (%u->%u): multiple SYN (%u, %u)\n",
				 &peer->addr, c->port_src, c->port_dst,
				 seq, c->syn_seq);
			return;
		}
		if (syn && !c->syn_seen) {
			c->syn_seq = seq;
			c->expect = seq + 1;
			c->syn_seen = true;
		}
	}

	data = (uint8_t *)tcp + (tcp->th_off << 2);
	if (data > end) {
		printfrr("\033[31m%u beyond end?\033[m\n", data - end);
		return;
	}

	if (syn) {
		if (data != end)
			printfrr("\033[31m%d data on SYN?\033[m\n", end - data);
		return;
	}

	if (!c->syn_seen) {
		if (DEBUG)
			printfrr("\033[91m%pSU non-SYN\033[m\n", &c->peer->addr);
		return;
	}

	if (data != end) {
		assert(data < end);

		size_t len = end - data;
		struct seg *seg = NULL, *prev = NULL, *now;
		int32_t tail_overlap = 0;

		frr_each (segs, c->segs, seg) {
			int32_t delta_s = seq - seg->seq;

			if (delta_s == 0 && len == seg->len)
				goto out;
			if (seg->seq >= seq)
				break;
			prev = seg;
		}

		if (prev)
			tail_overlap = (uint32_t)(prev->seq + prev->len) - seq;
		else if ((int32_t)(seq - c->expect) < 0)
			tail_overlap = MIN(c->expect - seq, len);

		if (tail_overlap > 0) {
			printfrr("\033[%dm%pSU %u->%u @%u tail overlap removing %d of %zd\033[m\n",
				 tail_overlap == (int32_t)len ? 33 : 31,
				 &c->peer->addr, c->port_src, c->port_dst, seq,
				 tail_overlap, len);
			seq += tail_overlap;
			len -= tail_overlap;
			data += tail_overlap;

			if (len == 0)
				goto out;
		}

		now = calloc(1, sizeof(*now));
		now->seq = seq;
		now->ts = ts;
		now->data = data;
		now->len = len;

		while (now && seg && (int32_t)((uint32_t)(seq + len) - seg->seq) > 0) {
			uint32_t keep = seg->seq - seq;

			printfrr("\033[%dm%pSU %u->%u %u head overlap keeping %u of %zd\033[m\n",
				 keep ? 31 : 33,
				 &c->peer->addr, c->port_src, c->port_dst, seq,
				 keep, len);

			if (keep) {
				now->len = keep;
				segs_add_after(c->segs, prev, now);
				now = NULL;
			}

			uint32_t delta = (uint32_t)(seg->seq + seg->len) - seq;

			if (delta >= len) {
				free(now);
				now = NULL;
				break;
			}

			seq += delta;
			data += delta;
			len -= delta;

			if (!now)
				now = calloc(1, sizeof(*now));
			now->seq = seq;
			now->ts = ts;
			now->data = data;
			now->len = len;

			prev = seg;
			seg = segs_next(c->segs, seg);
		}

		if (now)
			segs_add_after(c->segs, prev, now);
	}
out:

	struct seg *seg;
	size_t nseg = segs_count(c->segs);

	if (nseg > 16 || DEBUG) {
		int n = 0;

		printfrr("%pSU %u->%u: %u segments / nextmsg %u / e-s %u (%u) ====\n",
			 &c->peer->addr, c->port_src, c->port_dst,
			 nseg, c->nextmsg, c->expect - c->syn_seq, c->syn_seq);

		frr_each (segs, c->segs, seg) {
			if (n < 4 || n > (int)(nseg - 4))
				printfrr("%d: %5u+%4u=%5u\n", n, seg->seq - c->expect, seg->len,
					 seg->seq - c->expect + seg->len);
			n++;
		}
	}

	static uint8_t msgbuf[65536];

	do {
		uint32_t expect = c->expect;

		frr_each (segs, c->segs, seg) {
			if (seg->seq != expect)
				break;
			expect += seg->len;
		}

		if (expect == c->expect)
			break;

		if (c->nextmsg == 0 && expect - c->expect >= 18) {
			uint8_t bbuf[18];

			linearize(c, bbuf, 18, false);
			for (int i = 0; i < 16; i++)
				assert(bbuf[i] == 0xff);

			c->nextmsg = ((unsigned)bbuf[16] << 8) | bbuf[17];
			if (DEBUG)
				printfrr("nextmsg: %u\n", c->nextmsg);
		}

		if (!c->nextmsg || expect - c->expect < c->nextmsg)
			break;

		uint64_t msgts = linearize(c, msgbuf, c->nextmsg, true);

		if (DEBUG)
			printfrr("%u processable; e-s %u\n", c->nextmsg, c->expect - c->syn_seq);

		handle_bgp(c, msgbuf, c->nextmsg, msgts);

		c->nextmsg = 0;
	} while (true);
}

int main(int argc, char **argv)
{
	struct peers_head peers[1];
	const char *fn, *rn;
	int fd;
	struct stat st;
	const uint8_t *b, *c, *e, *hdr_end;
	bool mixed = false;
	char rlinebuf[256], *rline;

	peers_init(peers);

	assert(argc >= 3);
	fn = argv[1];
	rn = argv[2];

	FILE *locals = fopen(rn, "r");
	if (!locals) {
		perror(rn);
		return 1;
	}

	while ((rline = fgets(rlinebuf, sizeof(rlinebuf), locals))) {
		struct peer ref, *p;
		char *nl = strchr(rline, '\n');

		memset(&ref, 0, sizeof(ref));

		if (nl)
			*nl = '\0';

		char *colon = strchr(rline, ':');

		if (colon) {
			ref.addr.sin6.sin6_family = AF_INET6;
			if (inet_pton(AF_INET6, rline, &ref.addr.sin6.sin6_addr) != 1) {
				fprintf(stderr, "invalid v6 local: %s\n", rline);
				return 1;
			}
		} else {
			ref.addr.sin.sin_family = AF_INET;
			if (inet_pton(AF_INET, rline, &ref.addr.sin.sin_addr) != 1) {
				fprintf(stderr, "invalid v4 local: %s\n", rline);
				return 1;
			}
		}

		p = peers_find(peers, &ref);
		if (p)
			fprintf(stderr, "duplicate local: %s\n", rline);
		else {
			p = calloc(1, sizeof(*p));
			p->addr = ref.addr;
			p->dirfd = -2;
			p->fd = -2;
			convs_init(p->convs);
			peers_add(peers, p);
		}
	}

	fd = open(fn, O_RDONLY);
	if (fd < 0) {
		perror(fn);
		return 1;
	}

	assert(fstat(fd, &st) == 0);

	b = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	assert(b);

	c = hdr_end = b;
	e = c + st.st_size;

	while (c + 12 < e) {
		const struct blockhdr *bh = (const struct blockhdr *)c;
		const struct shb *shb;

		if (bh->block_len == 0 || bh->block_len == ~0U)
			break;
		if (c + bh->block_len > e) {
			printf("truncated, ending.\n");
			break;
		}

		switch (bh->block_type) {
		case 0x0a0d0d0a:
			shb = (const struct shb *)c;
			printf("SHB: %08x, %u.%u, %u\n", shb->bo_magic, shb->major, shb->minor, shb->section_len);
			if (shb->section_len == ~0U)
				printf("section is entire file\n");
			assert(!mixed);
			hdr_end = c + bh->block_len;
			break;
		case 0x1:
			//printf("interface definition\n");
			assert(!mixed);
			hdr_end = c + bh->block_len;
			break;
		case 0x6: {
			const struct epb *epb = (const struct epb *)c;
			uint64_t ts = ((uint64_t)epb->ts_hi << 32) | epb->ts_lo;
			const struct iphdr *ip4h;
			const struct ip6_hdr *ip6h;
			struct peer ref, *p;
			bool flip = false;

			memset(&ref, 0, sizeof(ref));
			mixed = true;
			//printf("packet @%u %llu %4u/%4u\n", epb->ifid, ts, epb->cap_len, epb->orig_len);

			assert(epb->cap_len == epb->orig_len);
			assert(epb->cap_len > 14);

			struct ethhdr *eth = (struct ethhdr *)epb->pkt;
			uint16_t *ep = &eth->h_proto;
			const struct tcphdr *tcp = NULL;
			uint16_t hl = 0;
			uint32_t payload = 0;

			if (ntohs(eth->h_proto) == 0x8100)
				ep += 2;

			switch (ntohs(*ep)) {
			case 0x0800:
				ip4h = (const struct iphdr *)(ep + 1);
				if (ip4h->protocol != IPPROTO_TCP)
					printfrr("non-tcp!");
				else
					tcp = (struct tcphdr *)((uint8_t *)(ep + 1) + (ip4h->ihl << 2));
				payload = ntohs(ip4h->tot_len) - (ip4h->ihl << 2);
				//printfrr("%39pI4 -> %-39pI4  %u\n", &ip4h->saddr, &ip4h->daddr, epb->cap_len);
				ref.addr.sin.sin_family = AF_INET;
				ref.addr.sin.sin_addr.s_addr = ip4h->saddr;
				p = peers_find(peers, &ref);
				if (p && p->fd == -2) {
					flip = true;
					ref.addr.sin.sin_addr.s_addr = ip4h->daddr;
					p = peers_find(peers, &ref);
				}
				goto common;
			case 0x86dd:
				ip6h = (const struct ip6_hdr *)(ep + 1);
				payload = ntohs(ip6h->ip6_plen);
				//printfrr("%39pI6 -> %-39pI6  %u\n", &ip6h->ip6_src, &ip6h->ip6_dst, epb->cap_len);
				ref.addr.sin6.sin6_family = AF_INET6;
				memcpy(&ref.addr.sin6.sin6_addr.s6_addr, &ip6h->ip6_src, 16);
				p = peers_find(peers, &ref);
				if (p && p->fd == -2) {
					flip = true;
					memcpy(&ref.addr.sin6.sin6_addr.s6_addr, &ip6h->ip6_dst, 16);
					p = peers_find(peers, &ref);
				}

				if (ip6h->ip6_nxt != IPPROTO_TCP)
					printfrr("non-tcp!");
				else
					tcp = (const struct tcphdr *)(ip6h + 1);
common:
				if (!p) {
					printfrr("new: %pSU\n", &ref.addr);

					snprintfrr(rlinebuf, sizeof(rlinebuf), "%pSU", &ref.addr);
					mkdir(rlinebuf, 0777);

					p = calloc(1, sizeof(*p));
					p->addr = ref.addr;
					p->fd = -1;
					p->dirfd = open(rlinebuf, O_DIRECTORY | O_RDONLY);
					if (p->dirfd < 0)
						printfrr("dirfd(%pSE): %m\n", rlinebuf);
					else {
						p->fd = -1; //openat(p->dirfd, "allc.pcapng", O_CREAT | O_EXCL | O_WRONLY, 0666);
						if (p->fd < 0)
							printfrr("creat(%pSE/allc.pcapng): %m\n", rlinebuf);
						else
							write(p->fd, b, hdr_end - b);
					}
					convs_init(p->convs);
					peers_add(peers, p);
				}
				if (p->fd >= 0)
					write(p->fd, c, bh->block_len);

				if (tcp && !flip)
					handle_tcp(p, tcp, (uint8_t *)tcp + payload, ts);
				break;
			default:
				printf("ignoring eth %04x\n", ntohs(*ep));
			}

			//printfrr("%.*pHX\n", 32, epb->pkt);
			break;
		}
		default:
			printf("block %08x len %u\n", bh->block_type, bh->block_len);
		}

		c += bh->block_len;
	}

	struct peer *p;

	frr_each (peers, peers, p) {
		struct conv *conv;

		frr_each (convs, p->convs, conv) {
			if (conv->ffd)
				fclose(conv->ffd);
		}
	}
	return 0;
}


