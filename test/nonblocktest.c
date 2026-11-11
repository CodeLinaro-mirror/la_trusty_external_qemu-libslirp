/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026 The Android Open Source Project
 *
 * Tests non-blocking UDP and ICMP host socket handling in libslirp.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "slirp.h"

static int64_t g_clock_ns = 1000LL * 1000 * 1000;

static int g_force_send_errno = 0;
static int g_force_recv_errno = 0;
static int g_intercept_target_fd = -1;
static int g_send_intercept_hits = 0;
static int g_recv_intercept_hits = 0;

typedef ssize_t (*sendto_fn)(int, const void *, size_t, int,
                             const struct sockaddr *, socklen_t);
typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *,
                               socklen_t *);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);

ssize_t sendto(int fd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    static sendto_fn real_sendto = NULL;
    if (!real_sendto) {
        real_sendto = (sendto_fn)dlsym(RTLD_NEXT, "sendto");
    }
    if (g_force_send_errno != 0 &&
        (g_intercept_target_fd == -1 || fd == g_intercept_target_fd)) {
        g_send_intercept_hits++;
        errno = g_force_send_errno;
        return -1;
    }
    return real_sendto(fd, buf, len, flags, dest_addr, addrlen);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    static recvfrom_fn real_recvfrom = NULL;
    if (!real_recvfrom) {
        real_recvfrom = (recvfrom_fn)dlsym(RTLD_NEXT, "recvfrom");
    }
    if (g_force_recv_errno != 0 &&
        (g_intercept_target_fd == -1 || fd == g_intercept_target_fd)) {
        g_recv_intercept_hits++;
        errno = g_force_recv_errno;
        return -1;
    }
    return real_recvfrom(fd, buf, len, flags, src_addr, addrlen);
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    static recv_fn real_recv = NULL;
    if (!real_recv) {
        real_recv = (recv_fn)dlsym(RTLD_NEXT, "recv");
    }
    if (g_force_recv_errno != 0 &&
        (g_intercept_target_fd == -1 || fd == g_intercept_target_fd)) {
        g_recv_intercept_hits++;
        errno = g_force_recv_errno;
        return -1;
    }
    return real_recv(fd, buf, len, flags);
}

static int g_icmp4_unreach_count = 0;
static int g_icmp6_error_count = 0;
static int g_udp4_rx_count = 0;
static int g_udp6_rx_count = 0;
static int g_icmp4_echoreply_count = 0;
static int g_icmp6_echoreply_count = 0;
static uint8_t g_last_udp_payload[64];
static size_t g_last_udp_payload_len = 0;

static Slirp *g_slirp = NULL;

static void cksum16(uint8_t *data, size_t size, uint8_t *out)
{
    uint32_t sum = 0;
    size_t i;

    out[0] = 0;
    out[1] = 0;
    for (i = 0; i + 1 < size; i += 2) {
        sum += (((uint16_t)data[i]) << 8) + data[i + 1];
    }
    if (i < size) {
        sum += ((uint16_t)data[i]) << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    out[0] = (sum >> 8) & 0xff;
    out[1] = sum & 0xff;
}

static uint16_t ipv6_upper_cksum(const uint8_t src[16], const uint8_t dst[16],
                                 uint8_t next_hdr, const uint8_t *upper,
                                 size_t upper_len)
{
    uint32_t sum = 0;
    size_t i;

    for (i = 0; i < 16; i += 2) {
        sum += ((uint16_t)src[i] << 8) | src[i + 1];
        sum += ((uint16_t)dst[i] << 8) | dst[i + 1];
    }
    sum += (upper_len >> 16) & 0xffff;
    sum += upper_len & 0xffff;
    sum += next_hdr;
    for (i = 0; i + 1 < upper_len; i += 2) {
        sum += ((uint16_t)upper[i] << 8) | upper[i + 1];
    }
    if (i < upper_len) {
        sum += ((uint16_t)upper[i] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t res = ~sum;
    return res == 0 && next_hdr == IPPROTO_UDP ? 0xffff : res;
}

static slirp_ssize_t send_packet_cb(const void *buf, size_t len, void *opaque)
{
    (void)opaque;
    const uint8_t *d = (const uint8_t *)buf;
    if (len < 14) {
        return (slirp_ssize_t)len;
    }
    uint16_t eth_type = ((uint16_t)d[12] << 8) | d[13];
    if (eth_type == 0x0806 && len >= 42 && d[20] == 0x00 && d[21] == 0x01) {
        uint8_t arp_reply[42] = {
            0x52, 0x55,  0x0a,  0x00,  0x02,  0x02,  0x52, 0x55, 0x0a,
            0x00, 0x02,  0x0f,  0x08,  0x06,  0x00,  0x01, 0x08, 0x00,
            0x06, 0x04,  0x00,  0x02,  0x52,  0x55,  0x0a, 0x00, 0x02,
            0x0f, d[38], d[39], d[40], d[41], 0x52,  0x55, 0x0a, 0x00,
            0x02, 0x02,  d[28], d[29], d[30], d[31],
        };
        slirp_input(g_slirp, arp_reply, sizeof(arp_reply));
        return (slirp_ssize_t)len;
    }
    if (eth_type == 0x0800 && len >= 34) {
        uint8_t proto = d[23];
        size_t ihl = (size_t)(d[14] & 0x0f) * 4;
        if (proto == IPPROTO_ICMP && len >= 14 + ihl + 8) {
            uint8_t icmp_type = d[14 + ihl];
            if (icmp_type == 3) {
                g_icmp4_unreach_count++;
            } else if (icmp_type == 0) {
                g_icmp4_echoreply_count++;
            }
        } else if (proto == IPPROTO_UDP && len >= 14 + ihl + 8) {
            size_t udp_len = (((size_t)d[14 + ihl + 4]) << 8) | d[14 + ihl + 5];
            if (udp_len >= 8 && len >= 14 + ihl + udp_len) {
                size_t plen = udp_len - 8;
                g_udp4_rx_count++;
                g_last_udp_payload_len = plen < sizeof(g_last_udp_payload) ?
                                             plen :
                                             sizeof(g_last_udp_payload);
                memcpy(g_last_udp_payload, d + 14 + ihl + 8,
                       g_last_udp_payload_len);
            }
        }
    } else if (eth_type == 0x86dd && len >= 54) {
        uint8_t nh = d[20];
        if (nh == IPPROTO_ICMPV6 && len >= 58) {
            uint8_t icmp6_type = d[54];
            if (icmp6_type == 135 && len >= 78) {
                uint8_t na[86];
                uint8_t guest_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f };
                memset(na, 0, sizeof(na));
                memcpy(na, d + 6, 6);
                memcpy(na + 6, guest_mac, 6);
                na[12] = 0x86;
                na[13] = 0xdd;
                na[14] = 0x60;
                na[18] = 0x00;
                na[19] = 32;
                na[20] = IPPROTO_ICMPV6;
                na[21] = 255;
                memcpy(na + 22, d + 62, 16);
                memcpy(na + 38, d + 22, 16);
                na[54] = 136;
                na[55] = 0;
                na[58] = 0x60;
                memcpy(na + 62, d + 62, 16);
                na[78] = 2;
                na[79] = 1;
                memcpy(na + 80, guest_mac, 6);
                uint16_t cs = ipv6_upper_cksum(na + 22, na + 38, IPPROTO_ICMPV6,
                                               na + 54, 32);
                na[56] = (cs >> 8) & 0xff;
                na[57] = cs & 0xff;
                slirp_input(g_slirp, na, sizeof(na));
            } else if (icmp6_type < 128) {
                g_icmp6_error_count++;
            } else if (icmp6_type == 129) {
                g_icmp6_echoreply_count++;
            }
        } else if (nh == IPPROTO_UDP && len >= 62) {
            size_t udp_len = (((size_t)d[58]) << 8) | d[59];
            if (udp_len >= 8 && len >= 54 + udp_len) {
                size_t plen = udp_len - 8;
                g_udp6_rx_count++;
                g_last_udp_payload_len = plen < sizeof(g_last_udp_payload) ?
                                             plen :
                                             sizeof(g_last_udp_payload);
                memcpy(g_last_udp_payload, d + 62, g_last_udp_payload_len);
            }
        }
    }
    return (slirp_ssize_t)len;
}

static void guest_error_cb(const char *msg, void *opaque)
{
    (void)opaque;
    fprintf(stderr, "guest_error: %s\n", msg);
}

static int64_t clock_get_ns_cb(void *opaque)
{
    (void)opaque;
    return g_clock_ns;
}

struct dummy_timer {
    SlirpTimerId id;
    void *cb_opaque;
    int64_t expire_ms;
};

static void *timer_new_opaque_cb(SlirpTimerId id, void *cb_opaque, void *opaque)
{
    (void)opaque;
    struct dummy_timer *t = calloc(1, sizeof(*t));
    t->id = id;
    t->cb_opaque = cb_opaque;
    return t;
}

static void timer_free_cb(void *timer, void *opaque)
{
    (void)opaque;
    free(timer);
}

static void timer_mod_cb(void *timer, int64_t expire_time, void *opaque)
{
    (void)opaque;
    struct dummy_timer *t = timer;
    t->expire_ms = expire_time;
}

static int g_registered_fds[64];
static int g_num_registered = 0;

static void register_poll_socket_cb(slirp_os_socket fd, void *opaque)
{
    (void)opaque;
    g_assert(fd >= 0);
    int fl = fcntl(fd, F_GETFL);
    g_assert(fl != -1);
    g_assert((fl & O_NONBLOCK) != 0);
    g_assert(g_num_registered < 64);
    g_registered_fds[g_num_registered++] = fd;
}

static void unregister_poll_socket_cb(slirp_os_socket fd, void *opaque)
{
    (void)opaque;
    for (int i = 0; i < g_num_registered; i++) {
        if (g_registered_fds[i] == fd) {
            g_registered_fds[i] = g_registered_fds[--g_num_registered];
            return;
        }
    }
    g_assert_not_reached();
}

static void notify_cb(void *opaque)
{
    (void)opaque;
}

struct poll_state {
    struct pollfd fds[64];
    int count;
    int forced_revents;
};

static int add_poll_cb(slirp_os_socket fd, int events, void *opaque)
{
    struct poll_state *ps = opaque;
    g_assert(ps->count < 64);
    short pe = 0;
    if (events & SLIRP_POLL_IN) {
        pe |= POLLIN;
    }
    if (events & SLIRP_POLL_OUT) {
        pe |= POLLOUT;
    }
    if (events & SLIRP_POLL_PRI) {
        pe |= POLLPRI;
    }
    if (events & SLIRP_POLL_ERR) {
        pe |= POLLERR;
    }
    if (events & SLIRP_POLL_HUP) {
        pe |= POLLHUP;
    }
    int idx = ps->count++;
    ps->fds[idx].fd = fd;
    ps->fds[idx].events = pe;
    ps->fds[idx].revents = 0;
    return idx;
}

static int get_revents_cb(int idx, void *opaque)
{
    struct poll_state *ps = opaque;
    if (ps->forced_revents != 0) {
        return ps->forced_revents;
    }
    int rev = 0;
    short r = ps->fds[idx].revents;
    if (r & POLLIN) {
        rev |= SLIRP_POLL_IN;
    }
    if (r & POLLOUT) {
        rev |= SLIRP_POLL_OUT;
    }
    if (r & POLLPRI) {
        rev |= SLIRP_POLL_PRI;
    }
    if (r & POLLERR) {
        rev |= SLIRP_POLL_ERR;
    }
    if (r & POLLHUP) {
        rev |= SLIRP_POLL_HUP;
    }
    return rev;
}

static int run_poll_once(int timeout_ms, int forced_revents)
{
    struct poll_state ps;
    memset(&ps, 0, sizeof(ps));
    ps.forced_revents = forced_revents;
    uint32_t t = (uint32_t)timeout_ms;
    slirp_pollfds_fill_socket(g_slirp, &t, add_poll_cb, &ps);
    int err = 0;
    if (forced_revents == 0 && ps.count > 0) {
        err = poll(ps.fds, (nfds_t)ps.count, timeout_ms);
    }
    slirp_pollfds_poll(g_slirp, err < 0, get_revents_cb, &ps);
    return ps.count;
}

static void send_guest_udp4(uint16_t sport, uint32_t dip_host_order,
                            uint16_t dport, const uint8_t *payload, size_t plen)
{
    uint8_t frame[256];
    g_assert(14 + 20 + 8 + plen <= sizeof(frame));
    memset(frame, 0, sizeof(frame));
    uint8_t dst_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };
    uint8_t src_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f };
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;

    uint16_t ip_len = (uint16_t)(20 + 8 + plen);
    frame[14] = 0x45;
    frame[16] = (ip_len >> 8) & 0xff;
    frame[17] = ip_len & 0xff;
    frame[22] = 64;
    frame[23] = IPPROTO_UDP;
    frame[26] = 10;
    frame[27] = 0;
    frame[28] = 2;
    frame[29] = 15;
    frame[30] = (dip_host_order >> 24) & 0xff;
    frame[31] = (dip_host_order >> 16) & 0xff;
    frame[32] = (dip_host_order >> 8) & 0xff;
    frame[33] = dip_host_order & 0xff;
    cksum16(frame + 14, 20, frame + 24);

    uint16_t udp_len = (uint16_t)(8 + plen);
    frame[34] = (sport >> 8) & 0xff;
    frame[35] = sport & 0xff;
    frame[36] = (dport >> 8) & 0xff;
    frame[37] = dport & 0xff;
    frame[38] = (udp_len >> 8) & 0xff;
    frame[39] = udp_len & 0xff;
    memcpy(frame + 42, payload, plen);

    slirp_input(g_slirp, frame, 14 + ip_len);
}

static void send_guest_udp6(uint16_t sport, const struct in6_addr *dst6,
                            uint16_t dport, const uint8_t *payload, size_t plen)
{
    uint8_t frame[256];
    g_assert(14 + 40 + 8 + plen <= sizeof(frame));
    memset(frame, 0, sizeof(frame));
    uint8_t dst_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };
    uint8_t src_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f };
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x86;
    frame[13] = 0xdd;
    frame[14] = 0x60;

    uint16_t udp_len = (uint16_t)(8 + plen);
    frame[18] = (udp_len >> 8) & 0xff;
    frame[19] = udp_len & 0xff;
    frame[20] = IPPROTO_UDP;
    frame[21] = 64;

    struct in6_addr src6;
    inet_pton(AF_INET6, "fec0::15", &src6);
    memcpy(frame + 22, &src6, 16);
    memcpy(frame + 38, dst6, 16);

    frame[54] = (sport >> 8) & 0xff;
    frame[55] = sport & 0xff;
    frame[56] = (dport >> 8) & 0xff;
    frame[57] = dport & 0xff;
    frame[58] = (udp_len >> 8) & 0xff;
    frame[59] = udp_len & 0xff;
    memcpy(frame + 62, payload, plen);
    uint16_t cs = ipv6_upper_cksum(frame + 22, frame + 38, IPPROTO_UDP,
                                   frame + 54, udp_len);
    frame[60] = (cs >> 8) & 0xff;
    frame[61] = cs & 0xff;

    slirp_input(g_slirp, frame, 14 + 40 + udp_len);
}

static void send_guest_icmp4_echo(uint32_t dip_host_order, uint16_t seq)
{
    uint8_t frame[46] = {
        0x52,
        0x55,
        0x0a,
        0x00,
        0x02,
        0x02,
        0x52,
        0x55,
        0x0a,
        0x00,
        0x02,
        0x0f,
        0x08,
        0x00,
        0x45,
        0x00,
        0x00,
        0x20,
        0x12,
        0x34,
        0x40,
        0x00,
        0x40,
        0x01,
        0x00,
        0x00,
        10,
        0,
        2,
        15,
        (uint8_t)(dip_host_order >> 24),
        (uint8_t)(dip_host_order >> 16),
        (uint8_t)(dip_host_order >> 8),
        (uint8_t)dip_host_order,
        0x08,
        0x00,
        0x00,
        0x00,
        0x01,
        0xec,
        (uint8_t)(seq >> 8),
        (uint8_t)seq,
        0xde,
        0xad,
        0xbe,
        0xef,
    };
    cksum16(frame + 14, 20, frame + 24);
    cksum16(frame + 34, 12, frame + 36);
    slirp_input(g_slirp, frame, sizeof(frame));
}

static void send_guest_icmp6_echo(const struct in6_addr *dst6, uint16_t seq)
{
    uint8_t frame[66];
    memset(frame, 0, sizeof(frame));
    uint8_t dst_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };
    uint8_t src_mac[6] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f };
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x86;
    frame[13] = 0xdd;
    frame[14] = 0x60;
    frame[18] = 0x00;
    frame[19] = 12;
    frame[20] = IPPROTO_ICMPV6;
    frame[21] = 64;
    struct in6_addr src6;
    inet_pton(AF_INET6, "fec0::15", &src6);
    memcpy(frame + 22, &src6, 16);
    memcpy(frame + 38, dst6, 16);
    frame[54] = 128;
    frame[55] = 0;
    frame[58] = 0x02;
    frame[59] = 0x01;
    frame[60] = (seq >> 8) & 0xff;
    frame[61] = seq & 0xff;
    frame[62] = 0xca;
    frame[63] = 0xfe;
    frame[64] = 0xba;
    frame[65] = 0xbe;
    uint16_t cs = ipv6_upper_cksum(frame + 22, frame + 38, IPPROTO_ICMPV6,
                                   frame + 54, 12);
    frame[56] = (cs >> 8) & 0xff;
    frame[57] = cs & 0xff;
    slirp_input(g_slirp, frame, sizeof(frame));
}

static SlirpCb g_callbacks = {
    .send_packet = send_packet_cb,
    .guest_error = guest_error_cb,
    .clock_get_ns = clock_get_ns_cb,
    .timer_new_opaque = timer_new_opaque_cb,
    .timer_free = timer_free_cb,
    .timer_mod = timer_mod_cb,
    .register_poll_socket = register_poll_socket_cb,
    .unregister_poll_socket = unregister_poll_socket_cb,
    .notify = notify_cb,
};

int main(void)
{
    alarm(5);
    SlirpConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.version = 6;
    cfg.in_enabled = true;
    cfg.vnetwork.s_addr = htonl(0x0a000200);
    cfg.vnetmask.s_addr = htonl(0xffffff00);
    cfg.vhost.s_addr = htonl(0x0a000202);
    cfg.vdhcp_start.s_addr = htonl(0x0a00020f);
    cfg.vnameserver.s_addr = htonl(0x0a000203);
    cfg.in6_enabled = true;
    inet_pton(AF_INET6, "fec0::", &cfg.vprefix_addr6);
    cfg.vprefix_len = 64;
    cfg.vhost6 = cfg.vprefix_addr6;
    cfg.vhost6.s6_addr[15] = 2;
    cfg.vnameserver6 = cfg.vprefix_addr6;
    cfg.vnameserver6.s6_addr[15] = 3;

    g_slirp = slirp_new(&cfg, &g_callbacks, NULL);
    g_assert(g_slirp != NULL);
    run_poll_once(0, 0);

    /* 1. UDPv4: would-block on first packet preserves SS_ISFCONNECTED &
     * refreshes so_expire */
    int srv4 = socket(AF_INET, SOCK_DGRAM, 0);
    g_assert(srv4 >= 0);
    struct sockaddr_in sin4;
    memset(&sin4, 0, sizeof(sin4));
    sin4.sin_family = AF_INET;
    sin4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = bind(srv4, (struct sockaddr *)&sin4, sizeof(sin4));
    g_assert(rc == 0);
    socklen_t sin4_len = sizeof(sin4);
    rc = getsockname(srv4, (struct sockaddr *)&sin4, &sin4_len);
    g_assert(rc == 0);
    uint16_t port4 = ntohs(sin4.sin_port);

    const uint8_t msg4[] = "hello-udp4";
    g_send_intercept_hits = 0;
    g_force_send_errno = ENOBUFS;
    send_guest_udp4(40001, 0x0a000202, port4, msg4, sizeof(msg4) - 1);
    g_force_send_errno = 0;
    g_assert(g_send_intercept_hits == 1);
    g_assert(g_icmp4_unreach_count == 0);
    g_assert(g_num_registered == 1);
    g_assert((g_slirp->udb.so_next->so_state & SS_ISFCONNECTED) != 0);
    int polled = run_poll_once(0, 0);
    g_assert(polled == 1);

    /* Advance 200s (< SO_EXPIRE=240s), trigger EAGAIN send to refresh
     * so_expire, then advance 100s more (total 300s > initial 240s): socket
     * must remain alive */
    g_clock_ns += 200LL * 1000 * 1000 * 1000;
    run_poll_once(0, 0);
    g_force_send_errno = EAGAIN;
    send_guest_udp4(40001, 0x0a000202, port4, msg4, sizeof(msg4) - 1);
    g_force_send_errno = 0;
    g_clock_ns += 100LL * 1000 * 1000 * 1000;
    polled = run_poll_once(0, 0);
    g_assert(polled == 1);

    /* Spurious POLLIN wakeup when socket has no packet (recvfrom -> EAGAIN) */
    run_poll_once(0, SLIRP_POLL_IN);
    g_assert(g_icmp4_unreach_count == 0);

    /* Guest retransmit succeeds and receives reply */
    send_guest_udp4(40001, 0x0a000202, port4, msg4, sizeof(msg4) - 1);
    struct pollfd srv4_pfd = { .fd = srv4, .events = POLLIN };
    rc = poll(&srv4_pfd, 1, 500);
    g_assert(rc == 1);
    uint8_t rxbuf[64];
    struct sockaddr_in peer4;
    socklen_t peer4_len = sizeof(peer4);
    ssize_t n = recvfrom(srv4, rxbuf, sizeof(rxbuf), 0,
                         (struct sockaddr *)&peer4, &peer4_len);
    g_assert(n == (ssize_t)(sizeof(msg4) - 1));
    ssize_t sent =
        sendto(srv4, rxbuf, (size_t)n, 0, (struct sockaddr *)&peer4, peer4_len);
    g_assert(sent == n);
    for (int i = 0; i < 10 && g_udp4_rx_count == 0; i++) {
        run_poll_once(10, 0);
    }
    g_assert(g_udp4_rx_count == 1);
    g_assert(g_last_udp_payload_len == sizeof(msg4) - 1);
    g_assert(memcmp(g_last_udp_payload, msg4, sizeof(msg4) - 1) == 0);
    close(srv4);

    /* 2. UDPv6: would-block + spurious EAGAIN + round-trip */
    int srv6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (srv6 >= 0) {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_loopback;
        if (bind(srv6, (struct sockaddr *)&sin6, sizeof(sin6)) == 0) {
            socklen_t sin6_len = sizeof(sin6);
            rc = getsockname(srv6, (struct sockaddr *)&sin6, &sin6_len);
            g_assert(rc == 0);
            uint16_t port6 = ntohs(sin6.sin6_port);

            const uint8_t msg6[] = "hello-udp6";
            g_force_send_errno = ENOBUFS;
            send_guest_udp6(40002, &cfg.vhost6, port6, msg6, sizeof(msg6) - 1);
            g_force_send_errno = 0;
            g_assert(g_icmp6_error_count == 0);
            g_assert(g_num_registered == 2);
            polled = run_poll_once(0, 0);
            g_assert(polled == 2);

            run_poll_once(0, SLIRP_POLL_IN);
            g_assert(g_icmp6_error_count == 0);

            send_guest_udp6(40002, &cfg.vhost6, port6, msg6, sizeof(msg6) - 1);
            struct pollfd srv6_pfd = { .fd = srv6, .events = POLLIN };
            rc = poll(&srv6_pfd, 1, 500);
            g_assert(rc == 1);
            struct sockaddr_in6 peer6;
            socklen_t peer6_len = sizeof(peer6);
            n = recvfrom(srv6, rxbuf, sizeof(rxbuf), 0,
                         (struct sockaddr *)&peer6, &peer6_len);
            g_assert(n == (ssize_t)(sizeof(msg6) - 1));
            sent = sendto(srv6, rxbuf, (size_t)n, 0, (struct sockaddr *)&peer6,
                          peer6_len);
            g_assert(sent == n);
            for (int i = 0; i < 10 && g_udp6_rx_count == 0; i++) {
                run_poll_once(10, 0);
            }
            g_assert(g_udp6_rx_count == 1);
            g_assert(memcmp(g_last_udp_payload, msg6, sizeof(msg6) - 1) == 0);

            /* 3. udpx_listen (so->so_m == NULL): EAGAIN & non-EAGAIN error must
             * not crash */
            struct sockaddr_in6 haddr6, gaddr6;
            memset(&haddr6, 0, sizeof(haddr6));
            haddr6.sin6_family = AF_INET6;
            haddr6.sin6_addr = in6addr_loopback;
            memset(&gaddr6, 0, sizeof(gaddr6));
            gaddr6.sin6_family = AF_INET6;
            inet_pton(AF_INET6, "fec0::15", &gaddr6.sin6_addr);
            gaddr6.sin6_port = htons(9999);
            rc = slirp_add_hostxfwd(g_slirp, (struct sockaddr *)&haddr6,
                                    sizeof(haddr6), (struct sockaddr *)&gaddr6,
                                    sizeof(gaddr6), SLIRP_HOSTFWD_UDP);
            g_assert(rc == 0);
            int listen_fd6 = g_registered_fds[g_num_registered - 1];
            run_poll_once(0, SLIRP_POLL_IN);
            g_assert(g_icmp6_error_count == 0);

            g_intercept_target_fd = listen_fd6;
            g_force_recv_errno = EHOSTUNREACH;
            g_recv_intercept_hits = 0;
            run_poll_once(0, SLIRP_POLL_IN);
            g_force_recv_errno = 0;
            g_intercept_target_fd = -1;
            g_assert(g_recv_intercept_hits == 1);

            /* 4. udp_reattach across address families unregisters old fd & sets
             * O_NONBLOCK */
            int reg_before_reattach = g_num_registered;
            struct sockaddr_storage dns6_ss;
            memset(&dns6_ss, 0, sizeof(dns6_ss));
            struct sockaddr_in6 *dns6 = (struct sockaddr_in6 *)&dns6_ss;
            dns6->sin6_family = AF_INET6;
            dns6->sin6_addr = in6addr_loopback;
            dns6->sin6_port = htons(53);
            slirp_init_custom_dns_servers(g_slirp, &dns6_ss, 1);
            g_force_send_errno = ENOBUFS;
            send_guest_udp4(40001, 0x0a000203, 53, msg4, sizeof(msg4) - 1);
            g_force_send_errno = 0;
            struct sockaddr_storage reattached_sa;
            socklen_t reattached_len = sizeof(reattached_sa);
            rc =
                getsockname(g_slirp->udb.so_prev->s,
                            (struct sockaddr *)&reattached_sa, &reattached_len);
            g_assert(rc == 0);
            g_assert(reattached_sa.ss_family == AF_INET6);
            g_assert(g_num_registered == reg_before_reattach);
        }
        close(srv6);
    }

    /* 5. ICMPv4 / ICMPv6 ping sockets (when permitted on host, e.g. macOS or
     * ping_group_range) */
    int probe4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (probe4 >= 0) {
        close(probe4);
        int reg_before = g_num_registered;
        g_force_send_errno = ENOBUFS;
        send_guest_icmp4_echo(0x7f000001, 1);
        g_force_send_errno = 0;
        g_assert(g_icmp4_unreach_count == 0);
        g_assert(g_num_registered == reg_before);
        g_assert(g_slirp->icmp.so_next == &g_slirp->icmp);

        send_guest_icmp4_echo(0x7f000001, 2);
        g_assert(g_num_registered == reg_before + 1);
        int icmp4_fd = g_registered_fds[g_num_registered - 1];
        g_intercept_target_fd = icmp4_fd;
        g_force_recv_errno = EAGAIN;
        run_poll_once(0, SLIRP_POLL_IN);
        g_force_recv_errno = 0;
        g_intercept_target_fd = -1;
        g_assert(g_num_registered == reg_before + 1);
        g_assert(g_icmp4_unreach_count == 0);
        for (int i = 0; i < 20 && g_icmp4_echoreply_count == 0; i++) {
            run_poll_once(10, 0);
        }
        g_assert(g_icmp4_echoreply_count == 1);
        g_assert(g_num_registered == reg_before);
    }

    int probe6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (probe6 >= 0) {
        close(probe6);
        int reg_before = g_num_registered;
        struct in6_addr loop6 = in6addr_loopback;
        g_force_send_errno = ENOBUFS;
        send_guest_icmp6_echo(&loop6, 1);
        g_force_send_errno = 0;
        g_assert(g_icmp6_error_count == 0);
        g_assert(g_num_registered == reg_before);
        g_assert(g_slirp->icmp.so_next == &g_slirp->icmp);

        send_guest_icmp6_echo(&loop6, 2);
        g_assert(g_num_registered == reg_before + 1);
        int icmp6_fd = g_registered_fds[g_num_registered - 1];
        g_intercept_target_fd = icmp6_fd;
        g_force_recv_errno = EAGAIN;
        run_poll_once(0, SLIRP_POLL_IN);
        g_force_recv_errno = 0;
        g_intercept_target_fd = -1;
        g_assert(g_num_registered == reg_before + 1);
        g_assert(g_icmp6_error_count == 0);
        for (int i = 0; i < 20 && g_icmp6_echoreply_count == 0; i++) {
            run_poll_once(10, 0);
        }
        g_assert(g_icmp6_echoreply_count == 1);
        g_assert(g_num_registered == reg_before);
    }

    slirp_cleanup(g_slirp);
    g_assert(g_num_registered == 0);
    printf("nonblocktest: udp4=%d udp6=%d icmp4=%d icmp6=%d ok\n",
           g_udp4_rx_count, g_udp6_rx_count, g_icmp4_echoreply_count,
           g_icmp6_echoreply_count);
    return 0;
}
