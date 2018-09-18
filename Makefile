#
# Copyright (c) 2012-2013 Takayuki Usui
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
default:all

srcdir = .
prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
sbindir = $(exec_prefix)/sbin
libexecdir = $(exec_prefix)/libexec
datadir = $(prefix)/share

IP_VERSION = 4
CC = gcc
CPPFLAGS = -DHAVE_CONFIG_H -I. -Ilwip-contrib/ports/unix/port/include \
  -Ilwip/src/include/ipv$(IP_VERSION) -Ilwip/src/include \
  -Ilwip-contrib/apps/chargen -Ilwip-contrib/apps/httpserver \
  -Ilwip-contrib/apps/tcpecho -Ilwip-contrib/apps/udpecho 
CFLAGS =  -Wall -g -O2
LDFLAGS = -lpthread -lutil
LIBS = 
INSTALL = /usr/bin/install -c
# \
lwip/src/apps/altcp_tls/altcp_tls_mbedtls_mem.c  \
lwip/src/apps/altcp_tls/altcp_tls_mbedtls.c  \
lwip/src/apps/http/http_client.c \
lwip/src/apps/http/makefsdata/makefsdata.c \
lwip/src/apps/http/altcp_proxyconnect.c \
lwip/src/apps/http/httpd.c \
lwip/src/apps/http/fs.c \
lwip/src/apps/http/fsdata.c \
lwip/src/apps/tftp/tftp_server.c \
lwip/src/apps/mqtt/mqtt.c \
lwip/src/apps/smtp/smtp.c \
lwip/src/apps/sntp/sntp.c \
lwip/src/apps/mdns/mdns.c \
lwip/src/apps/snmp/snmp_raw.c \
lwip/src/apps/snmp/snmp_snmpv2_framework.c \
lwip/src/apps/snmp/snmp_mib2_icmp.c \
lwip/src/apps/snmp/snmp_pbuf_stream.c \
lwip/src/apps/snmp/snmp_asn1.c \
lwip/src/apps/snmp/snmpv3_mbedtls.c \
lwip/src/apps/snmp/snmp_scalar.c \
lwip/src/apps/snmp/snmp_netconn.c \
lwip/src/apps/snmp/snmp_mib2_udp.c \
lwip/src/apps/snmp/snmp_mib2_interfaces.c \
lwip/src/apps/snmp/snmp_mib2.c \
lwip/src/apps/snmp/snmp_mib2_tcp.c \
lwip/src/apps/snmp/snmp_mib2_snmp.c \
lwip/src/apps/snmp/snmp_mib2_ip.c \
lwip/src/apps/snmp/snmp_core.c \
lwip/src/apps/snmp/snmp_msg.c \
lwip/src/apps/snmp/snmp_snmpv2_usm.c \
lwip/src/apps/snmp/snmp_threadsync.c \
lwip/src/apps/snmp/snmp_traps.c \
lwip/src/apps/snmp/snmp_mib2_system.c \
lwip/src/apps/snmp/snmpv3.c \
lwip/src/apps/snmp/snmp_table.c \
lwip/src/apps/lwiperf/lwiperf.c \
lwip/src/apps/netbiosns/netbiosns.c                 
SOURCES = \
lwip/src/core/pbuf.c \
lwip/src/core/memp.c \
lwip/src/core/raw.c \
lwip/src/core/udp.c \
lwip/src/core/ipv4/igmp.c \
lwip/src/core/ipv4/ip4.c \
lwip/src/core/ipv4/ip4_addr.c \
lwip/src/core/ipv4/icmp.c \
lwip/src/core/ipv4/ip4_frag.c \
lwip/src/core/ipv4/dhcp.c \
lwip/src/core/ipv4/etharp.c \
lwip/src/core/ipv4/autoip.c \
lwip/src/core/altcp_alloc.c \
lwip/src/core/timeouts.c \
lwip/src/core/ipv6/dhcp6.c \
lwip/src/core/ipv6/inet6.c \
lwip/src/core/ipv6/nd6.c \
lwip/src/core/ipv6/mld6.c \
lwip/src/core/ipv6/ip6_addr.c \
lwip/src/core/ipv6/ethip6.c \
lwip/src/core/ipv6/icmp6.c \
lwip/src/core/ipv6/ip6_frag.c \
lwip/src/core/ipv6/ip6.c \
lwip/src/core/altcp_tcp.c \
lwip/src/core/netif.c \
lwip/src/core/tcp_in.c \
lwip/src/core/tcp_out.c \
lwip/src/core/mem.c \
lwip/src/core/def.c \
lwip/src/core/inet_chksum.c \
lwip/src/core/stats.c \
lwip/src/core/ip.c \
lwip/src/core/tcp.c \
lwip/src/core/dns.c \
lwip/src/core/altcp.c \
lwip/src/core/init.c \
lwip/src/core/sys.c \
lwip/src/api/err.c \
lwip/src/api/sockets.c \
lwip/src/api/api_msg.c \
lwip/src/api/api_lib.c \
lwip/src/api/netbuf.c \
lwip/src/api/netifapi.c \
lwip/src/api/tcpip.c \
lwip/src/api/netdb.c \
lwip/src/api/if_api.c \
lwip/src/netif/bridgeif_fdb.c \
lwip/src/netif/bridgeif.c \
lwip/src/netif/slipif.c \
lwip/src/netif/lowpan6.c \
lwip/src/netif/lowpan6_common.c \
lwip/src/netif/ethernet.c \
lwip/src/netif/zepif.c \
lwip/src/netif/lowpan6_ble.c \
lwip/src/netif/ppp/ipv6cp.c \
lwip/src/netif/ppp/chap_ms.c \
lwip/src/netif/ppp/chap-md5.c \
lwip/src/netif/ppp/multilink.c \
lwip/src/netif/ppp/lcp.c \
lwip/src/netif/ppp/mppe.c \
lwip/src/netif/ppp/ppp.c \
lwip/src/netif/ppp/utils.c \
lwip/src/netif/ppp/ccp.c \
lwip/src/netif/ppp/eui64.c \
lwip/src/netif/ppp/fsm.c \
lwip/src/netif/ppp/auth.c \
lwip/src/netif/ppp/polarssl/md4.c \
lwip/src/netif/ppp/polarssl/md5.c \
lwip/src/netif/ppp/polarssl/arc4.c \
lwip/src/netif/ppp/polarssl/des.c \
lwip/src/netif/ppp/polarssl/sha1.c \
lwip/src/netif/ppp/chap-new.c \
lwip/src/netif/ppp/magic.c \
lwip/src/netif/ppp/pppos.c \
lwip/src/netif/ppp/pppoe.c \
lwip/src/netif/ppp/pppol2tp.c \
lwip/src/netif/ppp/ecp.c \
lwip/src/netif/ppp/eap.c \
lwip/src/netif/ppp/upap.c \
lwip/src/netif/ppp/ipcp.c \
lwip/src/netif/ppp/pppcrypt.c \
lwip/src/netif/ppp/pppapi.c \
lwip/src/netif/ppp/demand.c \
lwip/src/netif/ppp/vj.c \
lwip/src/apps/lwiperf/lwiperf.c \
lwip-contrib/ports/unix/port/sys_arch.c \
lwip-contrib/ports/unix/port/netif/list.c \
lwip-contrib/ports/unix/port/netif/pcapif.c \
lwip-contrib/ports/unix/port/netif/sio.c \
lwip-contrib/ports/unix/port/netif/fifo.c \
lwip-contrib/ports/unix/port/perf.c \
lwip-contrib/apps/udpecho_raw/udpecho_raw.c \
lwip-contrib/apps/ping/ping.c \
lwip-contrib/apps/socket_examples/socket_examples.c \
lwip-contrib/apps/tcpecho/tcpecho.c \
lwip-contrib/apps/tcpecho_raw/tcpecho_raw.c \
lwip-contrib/apps/rtp/rtp.c \
lwip-contrib/apps/netio/netio.c \
lwip-contrib/apps/shell/shell.c \
lwip-contrib/apps/udpecho/udpecho.c \
lwip-contrib/apps/chargen/chargen.c \
lwip-contrib/apps/httpserver/httpserver-netconn.c \
lwip-contrib/examples/lwiperf/lwiperf_example.c \
tapif.c
#lwip-contrib/ports/unix/port/netif/tapif.c \
#SOURCES = \
  lwip/src/api/api_lib.c \
  lwip/src/api/api_msg.c \
  lwip/src/api/err.c \
  lwip/src/api/netbuf.c \
  lwip/src/api/netdb.c \
  lwip/src/api/netifapi.c \
  lwip/src/api/sockets.c \
  lwip/src/api/tcpip.c \
  lwip/src/core/def.c \
  lwip/src/core/ipv4/dhcp.c \
  lwip/src/core/dns.c \
  lwip/src/core/init.c \
  lwip/src/core/mem.c \
  lwip/src/core/memp.c \
  lwip/src/core/netif.c \
  lwip/src/core/pbuf.c \
  lwip/src/core/raw.c \
  lwip/src/core/stats.c \
  lwip/src/core/sys.c \
  lwip/src/core/tcp.c \
  lwip/src/core/tcp_in.c \
  lwip/src/core/tcp_out.c \
  lwip/src/core/udp.c \
  lwip/src/core/ipv4/autoip.c \
  lwip/src/core/ipv4/icmp.c \
  lwip/src/core/ipv4/igmp.c \
  lwip/src/core/inet_chksum.c \
  lwip/src/core/ip.c \
  lwip/src/core/ipv4/ip_addr.c \
  lwip/src/core/ipv4/ip_frag.c \
  lwip/src/core/snmp/asn1_dec.c \
  lwip/src/core/snmp/asn1_enc.c \
  lwip/src/core/snmp/mib2.c \
  lwip/src/core/snmp/mib_structs.c \
  lwip/src/core/snmp/msg_in.c \
  lwip/src/core/snmp/msg_out.c \
  lwip/src/netif/etharp.c \
  lwip-contrib/ports/unix/sys_arch.c \
  lwip-contrib/apps/chargen/chargen.c \
  lwip-contrib/apps/httpserver/httpserver-netconn.c \
  lwip-contrib/apps/tcpecho/tcpecho.c \
  lwip-contrib/apps/udpecho/udpecho.c \
  tapif.c \
  lwip-tap.c

#OBJS := $(foreach f,$(SOURCES),$(notdir $(f:.c=.o)))
OBJS := $(foreach f,$(SOURCES),$(f:.c=.o))

%.o:%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

.PHONY: all check-syntax depend dep clean distclean

all: lwip-tap
lwip-tap: $(OBJS) lwip-tap.o
	$(CC) $(LIBS) -o lwip-tap $^ $(LDFLAGS) 
check-syntax:
	$(CC) $(CFLAGS) $(CPPFLAGS) -fsyntax-only #$(CHK_SOURCES)
depend dep:
	$(CC) $(CFLAGS) $(CPPFLAGS) -MM $(SOURCES) >.depend
clean:
	rm -f config.cache config.log
	rm -f lwip-tap $(OBJS) *~
distclean: clean
	rm -f Makefile config.h config.status
	rm -rf autom4te.cache
