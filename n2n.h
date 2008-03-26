/*
 * (C) 2007-08 - Luca Deri <deri@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
*/

#ifndef _N2N_H_
#define _N2N_H_

/*
   tunctl -t tun0
   tunctl -t tun1
   ifconfig tun0 1.2.3.4 up
   ifconfig tun1 1.2.3.5 up
   ./edge -d tun0 -l 2000 -r 127.0.0.1:3000 -c hello
   ./edge -d tun1 -l 3000 -r 127.0.0.1:2000 -c hello


   tunctl -u UID -t tunX
*/

#ifndef WIN32
#ifndef __linux__
#define _DARWIN_
#endif
#endif

#ifdef WIN32
#include "win32/n2n_win32.h"
#endif

#include <time.h>
#include <ctype.h>
#include <stdlib.h>

#ifndef WIN32
#include <netdb.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <pthread.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#include <syslog.h>
#include <sys/wait.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <string.h>
#ifdef WIN32
#include "win32/getopt.h"
#else
#define _GNU_SOURCE
#include <getopt.h>
#endif

#include <stdarg.h>

#ifdef WIN32
#include "win32/wintap.h"
#endif

#include "twofish.h"

#ifndef WIN32
typedef struct tuntap_dev {
  int fd;
  u_char mac_addr[6];
  u_int32_t ip_addr, device_mask;
  u_int mtu;
} tuntap_dev;

#define SOCKET int
#endif

#define QUICKLZ               1
#define N2N_VERSION           1

#define MSG_TYPE_REGISTER     1 /* FIX invece di usare il sender del pacchetto scriverlo nel pacchetto stesso */
#define MSG_TYPE_DEREGISTER   2
#define MSG_TYPE_PACKET       3
#define MSG_TYPE_REGISTER_ACK 4
#define MSG_TYPE_ACK_RESPONSE 5

#define COMMUNITY_LEN           16
#define MIN_COMPRESSED_PKT_LEN  32

enum packet_type {
  packet_unreliable_data = 0,  /* no ACK needed */
  packet_reliable_data,    /* needs ACK     */
  packet_ping,
  packet_pong
};

struct n2n_packet_header {
  u_int8_t version, msg_type, ttl, sent_by_supernode;
  char community_name[COMMUNITY_LEN], src_mac[6], dst_mac[6];
  struct sockaddr_in public_ip, private_ip;
  enum packet_type pkt_type;
  u_int32_t sequence_id;
  u_int32_t crc; // FIX - va gestito il CRC/md5 per beccare pacchetti forgiati
};

struct peer_info {
  char community_name[16], mac_addr[6];
  struct sockaddr_in public_ip, private_ip;
  time_t last_seen;
  struct peer_info *next;
  /* socket */
  int sock_fd;
  u_char is_udp_socket;
};

/* ************************************** */

struct packet_list {
  char *packet;
  u_int16_t packet_len;
  u_int16_t seq_id;
  struct packet_list *next;
};

struct send_hash_entry {
  char mac_addr[6];
  u_int16_t last_seq_id;
  u_int16_t last_ack_sequence_id;
  u_int16_t num_unacked_pkts;
  struct packet_list *unacked_packet_list;
  struct send_hash_entry *next;
};

#define MAX_NUM_UNACKED_PKTS  10

struct recv_hash_entry {
  char mac_addr[6];
  u_int32_t num_packets;
  u_int16_t last_acked_seq_id, last_rcvd_seq_id;
  struct recv_hash_entry *next;
};

/* ************************************** */

#define SEND_SEQ_ID_HASH_LEN      1024
#define RECV_SEQ_ID_HASH_LEN      SEND_SEQ_ID_HASH_LEN

#define REGISTER_FREQUENCY   10 /* sec */

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

/* ************************************** */

#define SUPERNODE_IP    "127.0.0.1"
#define SUPERNODE_PORT  1234

/* ************************************** */

#ifndef max
#define max(a, b) ((a < b) ? b : a)
#endif

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif

/* ************************************** */

/* Variables */
extern TWOFISH *tf;
extern int traceLevel;
extern char broadcast_addr[6];
extern char multicast_addr[6];

/* Functions */
extern int  init_n2n(char *encrypt_pwd);
extern void term_n2n();
extern void send_ack(int sock_fd, u_char is_udp_socket,
		     u_int16_t last_rcvd_seq_id,
		     struct n2n_packet_header *header,
		     struct sockaddr_in *remote_peer,
		     char *src_mac);

extern void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...);
extern int  tuntap_open(tuntap_dev *device, char *dev, char *device_ip, char *device_mask);
extern int  tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len);
extern int  tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len);
extern void tuntap_close(struct tuntap_dev *tuntap);

extern SOCKET open_socket(int local_port, int udp_sock, int server_mode);
extern int connect_socket(int sock_fd, struct sockaddr_in* dest);

extern void send_packet(int sock, u_char is_udp_socket,
			char *packet, size_t *packet_len,
			struct sockaddr_in *remote_peer,
			u_int8_t compress_data);
extern char* intoa(unsigned int addr, char* buf, u_short buf_len);
extern char* macaddr_str(char *mac, char *buf, int buf_len);
extern void fill_standard_header_fields(int sock, u_char use_udp_socket,
					struct n2n_packet_header *hdr,
					char *src_mac);

extern u_int receive_data(int sock_fd, u_char is_udp_socket,
			  char *packet, size_t packet_len, 
			  struct sockaddr_in *from, u_int8_t *discarded_pkt,
			  char *tun_mac_addr, u_int8_t decompress_data);
extern u_int reliable_sendto(int sock_fd, u_char is_udp_socket,
			     char *packet, size_t *packet_len, 
			     struct sockaddr_in *from, u_int8_t compress_data);
extern u_int unreliable_sendto(int sock_fd, u_char is_udp_socket,
			       char *packet, size_t *packet_len, 
			       struct sockaddr_in *from, u_int8_t compress_data);
extern u_int send_data(int sock_fd,  u_char is_udp_socket,
		       char *packet, size_t *packet_len, 
		       struct sockaddr_in *to, u_int8_t compress_data);
extern u_int8_t is_multi_broadcast(char *dest_mac);
extern char* msg_type2str(u_short msg_type);
extern void hexdump(char *buf, u_int len);

#endif /* _N2N_H_ */
