/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "lwip/opt.h"

#include "lwip/debug.h"
#include "lwip/def.h"
#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"

#include "tapif.h"

#define IFCONFIG_BIN "/sbin/ifconfig "

#if defined(LWIP_UNIX_LINUX)
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netpacket/packet.h>
/*
 * Creating a tap interface requires special privileges. If the interfaces
 * is created in advance with `tunctl -u <user>` it can be opened as a regular
 * user. The network must already be configured. If DEVTAP_IF is defined it
 * will be opened instead of creating a new tap device.
 *
 * You can also use PRECONFIGURED_TAPIF environment variable to do so.
 */
#ifndef DEVTAP_DEFAULT_IF
#define DEVTAP_DEFAULT_IF "tap0"
#endif
#ifndef DEVTAP
#define DEVTAP "/dev/net/tun"
#endif
//use this
#define NETMASK_ARGS "netmask %d.%d.%d.%d"
#define IFCONFIG_ARGS " inet %d.%d.%d.%d " NETMASK_ARGS
#elif defined(LWIP_UNIX_OPENBSD)
#define DEVTAP "/dev/tun0"
#define NETMASK_ARGS "netmask %d.%d.%d.%d"
#define IFCONFIG_ARGS "tun0 inet %d.%d.%d.%d " NETMASK_ARGS " link0"

#else /* others */

#define DEVTAP "/dev/tap0"
#define NETMASK_ARGS "netmask %d.%d.%d.%d"
#define IFCONFIG_ARGS "tap0 inet %d.%d.%d.%d " NETMASK_ARGS
#endif

/* Define those to better describe your network interface. */
#define IFNAME0 't'
#define IFNAME1 'p'

#ifndef TAPIF_DEBUG
#define TAPIF_DEBUG LWIP_DBG_OFF
#endif
#if 0
struct tapif {
    /* Add whatever per-interface state that is needed here. */
    int fd;
};
#endif

/* Forward declarations. */
static void tapif_input(struct netif *netif);
#if !NO_SYS
static void tapif_thread(void *arg);
#endif /* !NO_SYS */

static int do_tap(struct tapif *tap)
{
    int err = 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (!tap)
    {
        printf("tap is null\n");
        err = -1;
        return err;
    } 
    tap->fd = open(DEVTAP, O_RDWR);
    LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_init: fd %d\n", tap->fd));
    if (tap->fd == -1) {
        perror("tapif_init: try running \"modprobe tun\" or rebuilding your kernel with CONFIG_TUN; cannot open "DEVTAP);
        exit(1);
    }

    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name));
    ifr.ifr_name[sizeof(ifr.ifr_name)-1] = 0; /* ensure \0 termination */

    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    if (ioctl(tap->fd, TUNSETIFF, (void *) &ifr) < 0) {
        perror("tapif_init: "DEVTAP" ioctl TUNSETIFF");
        exit(1);
    }
    return err;
}
static int do_socket(struct tapif *tap)
{
    int err = 0;
    int listenfd;
    struct ifreq ifr;
    int ifidx = 0;
    struct sockaddr_ll fromaddr;

    if (!tap)
    {
        printf("tap is null\n");
        err = -1;
        return err;
    }

    if ((listenfd = socket(
                    //                    AF_INET,
                    PF_PACKET,
                    //                    SOCK_STREAM,
                    SOCK_RAW,
                    //                    htons(ETH_P_IP)))
                    //                    htons(ETH_P_ARP)))
        htons(ETH_P_ALL)))
            //                    0))
            < 0) 
            {
                perror("socket");
                exit(1);
            }
    bzero(&fromaddr, sizeof(fromaddr));
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tap->name, strlen(tap->name) + 1);
    if (ioctl(listenfd, SIOCGIFINDEX, &ifr) != 0)
    {
        perror("ioctl SIOCGIFINDEX fail");
        return -1;
    }
    ifidx = ifr.ifr_ifindex;
    printf("interface Index:%d\n", ifidx);
    fromaddr.sll_ifindex = ifidx;
    fromaddr.sll_family = PF_PACKET;
    fromaddr.sll_protocol=htons(ETH_P_ALL);//ETH_P_ALL);

    err = bind(listenfd, (struct sockaddr*)&fromaddr, sizeof(fromaddr));
    if (err < 0)
    {
        perror("bind err");
        return err;
    }
    //set promisc
    ifr.ifr_flags &= ~IFF_PROMISC;
    printf("name %s\n", ifr.ifr_name);
    if (ioctl(listenfd, SIOCSIFFLAGS, &ifr) < 0)
    {
        perror("set flag promisc");
        err = -5;
        return err;
    }
    return err;
}
/*-----------------------------------------------------------------------------------*/
static void low_level_init(struct netif *netif)
{
    struct tapif *tapif;
#if LWIP_IPV4
    int ret;
    char buf[1024];
#endif /* LWIP_IPV4 */
    char *preconfigured_tapif = getenv("PRECONFIGURED_TAPIF");

    tapif = (struct tapif *)netif->state;

    if (!tapif->name)
    {
        tapif->name ="tap0";
    }
    /* Obtain MAC address from network interface. */

    /* (We just fake an address...) */
    netif->hwaddr[0] = 0x02;
    netif->hwaddr[1] = 0x12;
    netif->hwaddr[2] = 0x34;
    netif->hwaddr[3] = 0x56;
    netif->hwaddr[4] = 0x78;
    netif->hwaddr[5] = 0xab;
    netif->hwaddr_len = 6;

    /* device capabilities */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;
#if 1
#if 1
    do_tap(tapif);
#else
    if (do_socket(tapif) < 0)
    {
        exit(2);
    }
#endif
#else
    tapif->fd = open(DEVTAP, O_RDWR);
    LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_init: fd %d\n", tapif->fd));
    if (tapif->fd == -1) {
#ifdef LWIP_UNIX_LINUX
        perror("tapif_init: try running \"modprobe tun\" or rebuilding your kernel with CONFIG_TUN; cannot open "DEVTAP);
#else /* LWIP_UNIX_LINUX */
        perror("tapif_init: cannot open "DEVTAP);
#endif /* LWIP_UNIX_LINUX */
        exit(1);
    }
#endif
#if 0
#ifdef LWIP_UNIX_LINUX
    {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        if (preconfigured_tapif) {
            strncpy(ifr.ifr_name, preconfigured_tapif, sizeof(ifr.ifr_name));
        } else {
            strncpy(ifr.ifr_name, tapif->name, sizeof(ifr.ifr_name));
        } 
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = 0; /* ensure \0 termination */

        ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
        if (ioctl(tapif->fd, TUNSETIFF, (void *) &ifr) < 0) {
            perror("tapif_init: "DEVTAP" ioctl TUNSETIFF");
            exit(1);
        }
    }
#endif /* LWIP_UNIX_LINUX */
#endif
    netif_set_link_up(netif);
    if (preconfigured_tapif == NULL) {
#if LWIP_IPV4
        snprintf(buf, 1024, IFCONFIG_BIN "%s" IFCONFIG_ARGS, tapif->name,
                ip4_addr1(netif_ip4_addr(netif)),
                ip4_addr2(netif_ip4_addr(netif)),
                ip4_addr3(netif_ip4_addr(netif)),
                ip4_addr4(netif_ip4_addr(netif))
#ifdef NETMASK_ARGS
                ,
                ip4_addr1(netif_ip4_netmask(netif)),
                ip4_addr2(netif_ip4_netmask(netif)),
                ip4_addr3(netif_ip4_netmask(netif)),
                ip4_addr4(netif_ip4_netmask(netif))
#endif /* NETMASK_ARGS */
                );

        LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_init: system(\"%s\");\n", buf));
        ret = system(buf);
        if (ret < 0) {
            perror("ifconfig failed");
            exit(1);
        }
        if (ret != 0) {
            printf("ifconfig returned %d\n", ret);
        }
#else /* LWIP_IPV4 */
        perror("todo: support IPv6 support for non-preconfigured tapif");
        exit(1);
#endif /* LWIP_IPV4 */
    }

#if !NO_SYS
    sys_thread_new("tapif_thread", tapif_thread, netif, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#endif /* !NO_SYS */
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_output():
 *
 * Should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 */
/*-----------------------------------------------------------------------------------*/

static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    struct tapif *tapif = (struct tapif *)netif->state;
    char buf[1518]; /* max packet size including VLAN excluding CRC */
    ssize_t written;

#if 0
    if (((double)rand()/(double)RAND_MAX) < 0.2) {
        printf("drop output\n");
        return ERR_OK; /* ERR_OK because we simulate packet loss on cable */
    }
#endif

    if (p->tot_len > sizeof(buf)) {
        MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
        perror("tapif: packet too large");
        return ERR_IF;
    }

    /* initiate transfer(); */
    pbuf_copy_partial(p, buf, p->tot_len, 0);

    /* signal that packet should be sent(); */
    written = write(tapif->fd, buf, p->tot_len);
    if (written < p->tot_len) {
        MIB2_STATS_NETIF_INC(netif, ifoutdiscards);
        perror("tapif: write");
        return ERR_IF;
    } else {
        MIB2_STATS_NETIF_ADD(netif, ifoutoctets, (u32_t)written);
        return ERR_OK;
    }
}
/*-----------------------------------------------------------------------------------*/
/*
 * low_level_input():
 *
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 */
/*-----------------------------------------------------------------------------------*/
static struct pbuf *low_level_input(struct netif *netif)
{
    struct pbuf *p;
    u16_t len;
    ssize_t readlen;
    char buf[1518]; /* max packet size including VLAN excluding CRC */
    struct tapif *tapif = (struct tapif *)netif->state;

    /* Obtain the size of the packet and put it into the "len"
       variable. */
    readlen = read(tapif->fd, buf, sizeof(buf));
    if (readlen < 0) {
        perror("read returned -1");
        exit(1);
    }
    len = (u16_t)readlen;

    MIB2_STATS_NETIF_ADD(netif, ifinoctets, len);

#if 0
    if (((double)rand()/(double)RAND_MAX) < 0.2) {
        printf("drop\n");
        return NULL;
    }
#endif

    /* We allocate a pbuf chain of pbufs from the pool. */
    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (p != NULL) {
        pbuf_take(p, buf, len);
        /* acknowledge that packet has been read(); */
    } else {
        /* drop packet(); */
        MIB2_STATS_NETIF_INC(netif, ifindiscards);
        LWIP_DEBUGF(NETIF_DEBUG, ("tapif_input: could not allocate pbuf\n"));
    }

    return p;
}

/*-----------------------------------------------------------------------------------*/
/*
 * tapif_input():
 *
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface.
 *
 */
/*-----------------------------------------------------------------------------------*/
static void tapif_input(struct netif *netif)
{
    struct pbuf *p = low_level_input(netif);

    if (p == NULL) {
#if LINK_STATS
        LINK_STATS_INC(link.recv);
#endif /* LINK_STATS */
        LWIP_DEBUGF(TAPIF_DEBUG, ("tapif_input: low_level_input returned NULL\n"));
        return;
    }

    if (netif->input(p, netif) != ERR_OK) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tapif_input: netif input error\n"));
        pbuf_free(p);
    }
}
static err_t low_level_probe(struct netif *netif,const char *name)
{
    int len;
    int s;
    struct ifreq ifr;
    len = strlen(name);
    if (len > (IFNAMSIZ-1)) {
        perror("tapif_init: name is too long");
        return ERR_IF;
    }
    s = socket(AF_INET,SOCK_DGRAM,0);
    if (s == -1) {
        perror("tapif_init: socket");
        return ERR_IF;
    }
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name,name,len);
    if (ioctl(s,SIOCGIFHWADDR,&ifr) == -1) {
        perror("tapif_init: ioctl SIOCGIFHWADDR");
        goto err;
    }
    u8_t* hwaddr = (u8_t*)&ifr.ifr_hwaddr.sa_data;
    netif->hwaddr[0] = hwaddr[0];
    netif->hwaddr[1] = hwaddr[1];
    netif->hwaddr[2] = hwaddr[2];
    netif->hwaddr[3] = hwaddr[3];
    netif->hwaddr[4] = hwaddr[4];
    netif->hwaddr[5] = hwaddr[5] ^ 1;
    netif->hwaddr_len = 6;
    if (ioctl(s,SIOCGIFMTU,&ifr) == -1) {
        perror("tapif_init: ioctl SIOCGIFMTU");
        goto err;
    }
    netif->mtu = ifr.ifr_mtu;
    close(s);
    return ERR_OK;
err:
    close(s);
    return ERR_IF;
}

/*-----------------------------------------------------------------------------------*/
/*
 * tapif_init():
 *
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 */
/*-----------------------------------------------------------------------------------*/
err_t tapif_init(struct netif *netif)
{
    struct tapif *tapif; 
    char *name = NULL;
    err_t err=0;
    if (!netif->state) 
    {
        tapif = (struct tapif *)mem_malloc(sizeof(struct tapif));
        if (tapif == NULL) {
            LWIP_DEBUGF(NETIF_DEBUG, ("tapif_init: out of memory for tapif\n"));
            return ERR_MEM;
        }
        netif->state = tapif;
    }
    else 
    {
        tapif = (struct tapif *)netif->state;
        name = tapif->name;
        if (!name)
        {
            err = low_level_probe(netif, name);
            if (err != ERR_OK)
            {
                return err;
            }
        }
    }

    MIB2_INIT_NETIF(netif, snmp_ifType_other, 100000000);

    netif->name[0] = IFNAME0;
    netif->name[1] = IFNAME1;
#if LWIP_IPV4
    netif->output = etharp_output;
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
    netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */
    netif->linkoutput = low_level_output;
    netif->mtu = 1500;

    low_level_init(netif);

    return ERR_OK;
}


/*-----------------------------------------------------------------------------------*/
void tapif_poll(struct netif *netif)
{
    tapif_input(netif);
}

#if NO_SYS

int tapif_select(struct netif *netif)
{
    fd_set fdset;
    int ret;
    struct timeval tv;
    struct tapif *tapif;
    u32_t msecs = sys_timeouts_sleeptime();

    tapif = (struct tapif *)netif->state;

    tv.tv_sec = msecs / 1000;
    tv.tv_usec = (msecs % 1000) * 1000;

    FD_ZERO(&fdset);
    FD_SET(tapif->fd, &fdset);

    ret = select(tapif->fd + 1, &fdset, NULL, NULL, &tv);
    if (ret > 0) {
        tapif_input(netif);
    }
    return ret;
}

#else /* NO_SYS */

static void tapif_thread(void *arg)
{
    struct netif *netif;
    struct tapif *tapif;
    fd_set fdset;
    int ret;

    netif = (struct netif *)arg;
    tapif = (struct tapif *)netif->state;

    while(1) {
        FD_ZERO(&fdset);
        FD_SET(tapif->fd, &fdset);

        /* Wait for a packet to arrive. */
        ret = select(tapif->fd + 1, &fdset, NULL, NULL, NULL);

        if(ret == 1) {
            /* Handle incoming packet. */
            tapif_input(netif);
        } else if(ret == -1) {
            perror("tapif_thread: select");
        }
    }
}

#endif /* NO_SYS */
