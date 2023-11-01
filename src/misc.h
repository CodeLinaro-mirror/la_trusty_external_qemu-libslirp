/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 1995 Danny Gasparovski.
 */

#ifndef MISC_H
#define MISC_H

#include "libslirp.h"

struct gfwd_list {
    SlirpWriteCb write_cb;
    void *opaque;
    union {
        struct in_addr ex_addr; /* IPv4 Server address */
        struct in6_addr ex_addr6; /* IPv6 Server address */
    } ip_body;
#define ex_addr6 ip_body.ex_addr6
#define ex_addr ip_body.ex_addr
    union {
        struct in_addr target_addr; /* IPv4 Destination address */
        struct in6_addr target_addr6; /* IPv6 Destination address */
    } target_ip_body;
#define target_addr6 target_ip_body.target_addr6
#define target_addr target_ip_body.target_addr
    int ex_fport; /* Port to telnet to */
    int target_port; /* Port to forward to on host side */
    char *ex_exec; /* Command line of what to exec */
    char *ex_unix; /* unix socket */
    struct gfwd_list *ex_next;
};

#define EMU_NONE 0x0

/* TCP emulations */
#define EMU_CTL 0x1
#define EMU_FTP 0x2
#define EMU_KSH 0x3
#define EMU_IRC 0x4
#define EMU_REALAUDIO 0x5
#define EMU_RLOGIN 0x6
#define EMU_IDENT 0x7

#define EMU_NOCONNECT 0x10 /* Don't connect */

struct tos_t {
    uint16_t lport;
    uint16_t fport;
    uint8_t tos;
    uint8_t emu;
};

struct emu_t {
    uint16_t lport;
    uint16_t fport;
    uint8_t tos;
    uint8_t emu;
    struct emu_t *next;
};

struct slirp_quehead {
    struct slirp_quehead *qh_link;
    struct slirp_quehead *qh_rlink;
};

/* Insert element a into queue b */
void slirp_insque(void *a, void *b);

/* Remove element a from its queue */
void slirp_remque(void *a);

/* Run the given command in the background, and expose its output as a socket */
int fork_exec(struct socket *so, const char *ex);

/* Create a Unix socket, and expose it as a socket */
int open_unix(struct socket *so, const char *unixsock);

/* Add a guest forward on the given address and port, with guest data being
 * forwarded by calling write_cb */
struct gfwd_list *add_guestfwd(struct gfwd_list **ex_ptr, SlirpWriteCb write_cb,
                               void *opaque, struct in_addr addr, int port);

/* Add a IPv6 guest forward on the given address and port, with guest data being
 * forwarded by calling write_cb */
struct gfwd_list *add_guestxfwd(struct gfwd_list **ex_ptr,
                                struct in6_addr *server_addr, int server_port,
                                struct in6_addr *destination_addr,
                                int destination_port);

/* Run the given command in the backaground, and send its output to the guest on
 * the given address and port */
struct gfwd_list *add_exec(struct gfwd_list **ex_ptr, const char *cmdline,
                           struct in_addr addr, int port);

/* Create a Unix socket, and expose it to the guest on the given address and
 * port */
struct gfwd_list *add_unix(struct gfwd_list **ex_ptr, const char *unixsock,
                           struct in_addr addr, int port);

/* Remove the guest forward bound to the given address and port */
int remove_guestfwd(struct gfwd_list **ex_ptr, struct in_addr addr, int port);

/* Remove the IPv6 guest forward bound to the given address and port */
int remove_guestxfwd(struct gfwd_list **ex_ptr, struct in6_addr *addr, int port);

/* Bind the socket to the outbound address specified in the slirp configuration */
int slirp_bind_outbound(struct socket *so, unsigned short af);

#endif
