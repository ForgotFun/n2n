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

#include "n2n.h"

#include "minilzo.h"

char broadcast_addr[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
char multicast_addr[6] = { 0x01, 0x00, 0x05, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */

struct send_hash_entry** send_seq_id_hash = NULL;
struct recv_hash_entry** recv_seq_id_hash = NULL;
TWOFISH *tf;

/* ************************************** */

int init_n2n(char *encrypt_pwd) {
#ifdef WIN32
  initWin32();
#endif

  tf = TwoFishInit(encrypt_pwd);

  if(lzo_init() != LZO_E_OK) {
    traceEvent(TRACE_ERROR, "LZO compression error");
    return(-1);
  }

  send_seq_id_hash = (struct send_hash_entry**)calloc(SEND_SEQ_ID_HASH_LEN,
						      sizeof(struct send_hash_entry*));
  if(send_seq_id_hash == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory!");
    return(-1);
  }

  recv_seq_id_hash = (struct recv_hash_entry**)calloc(RECV_SEQ_ID_HASH_LEN,
						      sizeof(struct recv_hash_entry*));
  if(recv_seq_id_hash == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory!");
    return(-1);
  }

  return(0);
}

/* ************************************** */

void term_n2n() {
  if(send_seq_id_hash) {
    int i;

    for(i=0; i<SEND_SEQ_ID_HASH_LEN; i++) {
      int j = 0;

      if(send_seq_id_hash[j] != NULL) {
	struct send_hash_entry *next, *scan = send_seq_id_hash[j];

	while(scan != NULL) {
	  struct packet_list *pkt_scan = scan->unacked_packet_list;
	  next = scan->next;

	  while(pkt_scan != NULL) {
	    struct packet_list *nxt;

	    free(pkt_scan->packet);
	    nxt = pkt_scan->next;
	    free(pkt_scan);
	    pkt_scan = nxt;
	  }

	  free(scan);
	  scan = next;
	}
      }
    }

    free(send_seq_id_hash);
  }

  if(recv_seq_id_hash) {
    int j = 0;

    if(recv_seq_id_hash[j] != NULL) {
      struct recv_hash_entry *next, *scan = recv_seq_id_hash[j];

      while(scan != NULL) {
	next = scan->next;
	free(scan);
	scan = next;
      }
    }

    free(recv_seq_id_hash);
  }

  TwoFishDestroy(tf);
}

/* ************************************** */

SOCKET open_socket(int local_port, int udp_sock, int server_mode) {
  SOCKET sock_fd;
  struct sockaddr_in local_address;
  int sockopt = 1;

  if((sock_fd = socket(PF_INET, udp_sock ? SOCK_DGRAM : SOCK_STREAM, 0))  < 0) {
    traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n",
	       strerror(errno), sock_fd);
    return(-1);
  }

#ifndef WIN32
  /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

  memset(&local_address, 0, sizeof(local_address));
  local_address.sin_family = AF_INET;
  local_address.sin_port = htons(local_port);
  local_address.sin_addr.s_addr = INADDR_ANY;
  if(bind(sock_fd, (struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
    traceEvent(TRACE_ERROR, "Bind error [%s]\n", strerror(errno));
    return(-1);
  }

  if((!udp_sock) && server_mode) {
    if(listen(sock_fd, 255) == -1) {
      traceEvent(TRACE_ERROR, "Listen error [%s]\n", strerror(errno));
      return(-1);
    }
  }

  return(sock_fd);
}

/* ************************************** */

int connect_socket(int sock_fd, struct sockaddr_in* dest) {
  char *http_header;
  int len, rc;

  rc = connect(sock_fd, (struct sockaddr*)dest, sizeof(struct sockaddr_in));

  if(rc == -1) {
    traceEvent(TRACE_WARNING, "connect() error [%s]\n", strerror(errno));
    return(-1);
  }

  /* Send dummy http header */
  http_header = "GET / HTTP/1.0\r\n\r\n";
  len = strlen(http_header);
  rc = send(sock_fd, http_header, len, 0);   

  return((rc == len) ? 0 : -1);
}


/* *********************************************** */

void send_packet(int sock, u_char is_udp_socket, 
		 char *packet, size_t *packet_len,
		 struct sockaddr_in *remote_peer, u_int8_t compress_data) {
  int data_sent_len;

  data_sent_len = unreliable_sendto(sock, is_udp_socket,
				    packet, packet_len, remote_peer, compress_data);

  if(data_sent_len != *packet_len)
    traceEvent(TRACE_WARNING,
	       "sendto() [sent=%d][attempted_to_send=%d] [%s]\n",
	       data_sent_len, *packet_len, strerror(errno));
}

/* *********************************************** */

int traceLevel = 2 /* NORMAL */;
int useSyslog = 0, syslog_opened = 0;

void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= traceLevel) {
    char buf[2048], out_buf[640];
    char theDate[32], *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
    snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate, file, line, extra_msg, buf);

#ifndef WIN32
    if(useSyslog) {
      if(!syslog_opened) {
        openlog("n2n", LOG_PID, LOG_DAEMON);
        syslog_opened = 1;
      }

      syslog(LOG_INFO, out_buf);
    } else
      printf("%s\n", out_buf);
#else
    printf("%s\n", out_buf);
#endif
  }

  fflush(stdout);
  va_end(va_ap);
}

/* *********************************************** */

char* intoa(unsigned int addr, char* buf, u_short buf_len) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[buf_len];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
        *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* *********************************************** */

char* macaddr_str(char *mac, char *buf, int buf_len) {
  snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
	   mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
	   mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);
  return(buf);
}

/* *********************************************** */

void fill_standard_header_fields(int sock, u_char is_udp_packet,
				 struct n2n_packet_header *hdr, char *src_mac) {
  socklen_t len = sizeof(hdr->private_ip);
  memset(hdr, 0, sizeof(struct n2n_packet_header));
  hdr->version = N2N_VERSION;
  hdr->crc = 0; // FIX
  if(src_mac != NULL) memcpy(hdr->src_mac, src_mac, 6);
  getsockname(sock, (struct sockaddr*)&hdr->private_ip, &len);
}

/* *********************************************** */

static u_int32_t hash_value(const u_int8_t *str, const u_int8_t str_len) {
  u_int32_t hash = 0, i;

  for(i = 0; i < str_len; i++) {
    hash = str[i] + (hash << 6) + (hash << 16) - hash;
  }

  return(hash % SEND_SEQ_ID_HASH_LEN);
}

/* *********************************************** */

void send_ack(int sock_fd, u_char is_udp_socket, 
	      u_int16_t last_rcvd_seq_id,
	      struct n2n_packet_header *header,
	      struct sockaddr_in *remote_peer,
	      char *src_mac) {
  struct n2n_packet_header hdr;
  size_t len = sizeof(hdr);

  fill_standard_header_fields(sock_fd, is_udp_socket, &hdr, src_mac);
  hdr.msg_type = MSG_TYPE_ACK_RESPONSE;
  hdr.sequence_id = last_rcvd_seq_id;
  memcpy(hdr.community_name, header->community_name, COMMUNITY_LEN);
  send_packet(sock_fd, is_udp_socket, (char*)&hdr, &len, remote_peer, 1);
}

/* *********************************************** */

u_int8_t is_multi_broadcast(char *dest_mac) {
  return(((!memcmp(broadcast_addr, dest_mac, 6))
	  || (!memcmp(multicast_addr, dest_mac, 3))) ? 1 : 0);
}

/* *********************************************** */

/* http://www.faqs.org/rfcs/rfc908.html */

u_int receive_data(int sock_fd, u_char is_udp_socket,
		   char *packet, size_t packet_len,
		   struct sockaddr_in *from, u_int8_t *discarded_pkt,
		   char *tun_mac_addr, u_int8_t decompress_data) {
  socklen_t fromlen = sizeof(struct sockaddr_in);
  int len;
  struct n2n_packet_header *hdr;
  char *payload, *pkt_type, src_mac_buf[32], dst_mac_buf[32], ip_buf[32], from_ip_buf[32];

  if(is_udp_socket)
    len = recvfrom(sock_fd, packet, packet_len, 0, (struct sockaddr*)from, &fromlen);
  else {
    len = recv(sock_fd, packet, 4, 0);
    if(len == 4) {
      packet[4] = '\0';
      len = atoi(packet);
      len = recv(sock_fd, packet, len, 0);
    } else {
      traceEvent(TRACE_WARNING, "Unable to receive n2n packet length");
      return(-1);
    }
  }

  hdr = (struct n2n_packet_header*)packet;
  payload = &packet[sizeof(struct n2n_packet_header)];

  if(len < 0) {
#ifdef WIN32
    if(WSAGetLastError() != WSAECONNRESET /* http://support.microsoft.com/kb/263823 */ ) {
      traceEvent(TRACE_WARNING, "recvfrom returned %d [err=%d]", len, WSAGetLastError());
    }
#endif
	return(0);
  } else if(len > MIN_COMPRESSED_PKT_LEN) {
    char decompressed[2048];
    int rc;
    lzo_uint decompressed_len;

    if(decompress_data) {
      rc = lzo1x_decompress((u_char*)&packet[sizeof(struct n2n_packet_header)], 
			    len-sizeof(struct n2n_packet_header),
			    (u_char*)decompressed, &decompressed_len, NULL);
      
      if(rc == LZO_E_OK)
	traceEvent(TRACE_INFO, "%u bytes decompressed into %u", len, decompressed_len);    
      
      if(packet_len > decompressed_len) {
	memcpy(&packet[sizeof(struct n2n_packet_header)], decompressed, decompressed_len);
	len = decompressed_len+sizeof(struct n2n_packet_header);
      } else {
	traceEvent(TRACE_WARNING, "Uncompressed packet is too large [decompressed_len=%d]",
		   decompressed_len);
	return(0);
      }
    }

    (*discarded_pkt) = 0;

    if(!hdr->sent_by_supernode)
      memcpy(&hdr->public_ip, from, sizeof(struct sockaddr_in));

    switch(hdr->pkt_type) {
    case packet_unreliable_data:
      pkt_type = "unreliable data";
      break;
    case packet_reliable_data:
      pkt_type = "reliable data";
      break;
    case packet_ping:
      pkt_type = "ping";
      break;
    case packet_pong:
      pkt_type = "pong";
      break;
    default:
      pkt_type = "???";
    }

    traceEvent(TRACE_INFO, "+++ Received %s packet [rcvd_from=%s:%d][msg_type=%s][seq_id=%d]",
	       pkt_type, 
	       intoa(ntohl(from->sin_addr.s_addr), from_ip_buf, sizeof(from_ip_buf)),
	       ntohs(from->sin_port),	       
	       msg_type2str(hdr->msg_type),
	       hdr->sequence_id);
    traceEvent(TRACE_INFO, "    [src_mac=%s][dst_mac=%s][original_sender=%s:%d]",
	       macaddr_str((char*)&payload[6], src_mac_buf, sizeof(src_mac_buf)),
	       macaddr_str((char*)payload, dst_mac_buf, sizeof(dst_mac_buf)),
	       intoa(ntohl(hdr->public_ip.sin_addr.s_addr), ip_buf, sizeof(ip_buf)),
	       ntohs(hdr->public_ip.sin_port));

#ifdef HANDLE_RETRANSMISSION
    if((hdr->pkt_type == packet_reliable_data)
       && (hdr->msg_type == MSG_TYPE_PACKET)) {
      (*discarded_pkt) = handle_ack(sock_fd,  is_udp_socket, hdr, 
				    &payload[6], payload, from, tun_mac_addr);
    } else
      (*discarded_pkt) = 0;
#endif
  } else
    traceEvent(TRACE_WARNING, "Receive error [%s] or pkt too short [len=%d]\n", 
	       strerror(errno), len);

  return(len);
}

/* *********************************************** */

static u_int32_t queue_packet(struct send_hash_entry *scan,
                       char *packet,
                       u_int16_t packet_len) {
  struct packet_list *pkt = (struct packet_list*)malloc(sizeof(struct packet_list));

  if(pkt == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory!");
    return(0);
  }

  if((pkt->packet = (char*)malloc(packet_len)) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory!");
    return(0);
  }

  memcpy(pkt->packet, packet, packet_len);
  pkt->packet_len = packet_len;
  pkt->seq_id = scan->last_seq_id;
  pkt->next = scan->unacked_packet_list;
  scan->unacked_packet_list = pkt;
  scan->num_unacked_pkts++;
  return(pkt->seq_id);
}

/* *********************************************** */

/* Used for sending packets out */
static u_int32_t mac2sequence(u_int8_t *mac_addr, char *packet,
		       u_int16_t packet_len) {
  u_int32_t hash_idx;
  u_int8_t is_dst_broad_multi_cast = ((!memcmp(broadcast_addr, mac_addr, 6))
				      || (!memcmp(multicast_addr, mac_addr, 3))) ? 1 : 0;
  struct send_hash_entry *scan;

  if(is_dst_broad_multi_cast)
    return(0);

  hash_idx = hash_value(mac_addr, 6);

  if(send_seq_id_hash[hash_idx] != NULL) {
    scan = send_seq_id_hash[hash_idx];

    if(memcmp(scan->mac_addr, mac_addr, 6) == 0) {
      scan->last_seq_id++;
      return(queue_packet(scan, packet, packet_len));
    } else
      scan = scan->next;
  }

  /* New entry */
  scan = (struct send_hash_entry*)calloc(1, sizeof(struct send_hash_entry));

  if(scan == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory!");
    return(0);
  }

  memcpy(scan->mac_addr, mac_addr, 6);
  scan->last_seq_id = 0;
  scan->next = send_seq_id_hash[hash_idx];
  send_seq_id_hash[hash_idx] = scan;

  return(queue_packet(scan, packet, packet_len));
}

/* *********************************************** */

/* Work-memory needed for compression. Allocate memory in units
 * of `lzo_align_t' (instead of `char') to make sure it is properly aligned.
 */

#define HEAP_ALLOC(var,size) \
    lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS);

/* ******************************************************* */

u_int send_data(int sock_fd, u_char is_udp_socket, 
		char *packet, size_t *packet_len, 
		struct sockaddr_in *to, u_int8_t compress_data) {
  char compressed[1600];
  int rc;
  lzo_uint compressed_len;

  if(*packet_len < sizeof(struct n2n_packet_header)) {
    traceEvent(TRACE_WARNING, "The packet about to be sent is too short [len=%d]\n", *packet_len);
    return(-1);
  }

  memcpy(compressed, packet, sizeof(struct n2n_packet_header));

  if(compress_data) {
    rc = lzo1x_1_compress((u_char*)&packet[sizeof(struct n2n_packet_header)], 
			  *packet_len - sizeof(struct n2n_packet_header),
			  (u_char*)&compressed[sizeof(struct n2n_packet_header)], 
			  &compressed_len, wrkmem);
    compressed_len += sizeof(struct n2n_packet_header);
    
    traceEvent(TRACE_INFO, "%u bytes compressed into %u", *packet_len, compressed_len);
    /* *packet_len = compressed_len; */
    
    if(is_udp_socket)
      rc = sendto(sock_fd, compressed, compressed_len, 0, 
		  (struct sockaddr*)to, sizeof(struct sockaddr_in));
    else {
      char send_len[5];

      /* 4 bytes packet length */
      snprintf(send_len, sizeof(send_len), "%04d", (int)compressed_len);
      if((rc = send(sock_fd, send_len, 4, 0)) != 4)
	return(-1);
      rc = send(sock_fd, compressed, compressed_len, 0);
    }
  } else {
    compressed_len = *packet_len;
    if(is_udp_socket)
      rc = sendto(sock_fd, packet, compressed_len, 0, 
		  (struct sockaddr*)to, sizeof(struct sockaddr_in));
    else {
      char send_len[5];

      /* 4 bytes packet length */
      snprintf(send_len, sizeof(send_len), "%04d", (int)compressed_len);
      if((rc = send(sock_fd, send_len, 4, 0)) != 4)
        return(-1);
      rc = send(sock_fd, compressed, compressed_len, 0);
    }
    
    if(rc == -1) {
      char ip_buf[32];

      traceEvent(TRACE_WARNING, "sendto() failed while attempting to send data to %s:%d",
		 intoa(ntohl(to->sin_addr.s_addr), ip_buf, sizeof(ip_buf)), 
		 ntohs(to->sin_port));
    }
  }

  if(rc == compressed_len)
    return(*packet_len); /* fake just to avoid warnings */
  else
    return(rc);
}

/* *********************************************** */

u_int reliable_sendto(int sock_fd, u_char is_udp_socket,
		      char *packet, size_t *packet_len, 
		      struct sockaddr_in *to, u_int8_t compress_data) {
  char *payload = &packet[sizeof(struct n2n_packet_header)];
  struct n2n_packet_header *hdr = (struct n2n_packet_header*)packet;
  char src_mac_buf[32], dst_mac_buf[32];

  hdr->sequence_id = (hdr->msg_type == MSG_TYPE_PACKET) ? mac2sequence((u_char*)payload, packet, *packet_len) : 0;
   hdr->pkt_type    = packet_reliable_data;

   traceEvent(TRACE_INFO, "Sent reliable packet [msg_type=%s][seq_id=%d][src_mac=%s][dst_mac=%s]",
	      msg_type2str(hdr->msg_type), hdr->sequence_id, 
	      macaddr_str(&packet[6], src_mac_buf, sizeof(src_mac_buf)),
	      macaddr_str(packet, dst_mac_buf, sizeof(dst_mac_buf)));

   return(send_data(sock_fd, is_udp_socket, 
		    packet, packet_len, to, compress_data));
}

/* *********************************************** */

u_int unreliable_sendto(int sock_fd, u_char is_udp_socket,
			char *packet, size_t *packet_len, 
			struct sockaddr_in *to, u_int8_t compress_data) {
  struct n2n_packet_header *hdr = (struct n2n_packet_header*)packet;
  char src_mac_buf[32], dst_mac_buf[32];

  hdr->sequence_id = 0; /* Unreliable messages have 0 as sequence number */
  hdr->pkt_type    = packet_unreliable_data;

  traceEvent(TRACE_INFO, "Sent unreliable packet [msg_type=%s][seq_id=%d][src_mac=%s][dst_mac=%s]",
	     msg_type2str(hdr->msg_type), hdr->sequence_id, 
	     macaddr_str(hdr->src_mac, src_mac_buf, sizeof(src_mac_buf)),
	     macaddr_str(hdr->dst_mac, dst_mac_buf, sizeof(dst_mac_buf)));

  return(send_data(sock_fd, is_udp_socket, 
		   packet, packet_len, to, compress_data));
}

/* *********************************************** */

char* msg_type2str(u_short msg_type) {
  switch(msg_type) {
  case MSG_TYPE_REGISTER: return("MSG_TYPE_REGISTER");
  case MSG_TYPE_DEREGISTER: return("MSG_TYPE_DEREGISTER");
  case MSG_TYPE_PACKET: return("MSG_TYPE_PACKET");
  case MSG_TYPE_REGISTER_ACK: return("MSG_TYPE_REGISTER_ACK");
  case MSG_TYPE_ACK_RESPONSE: return("MSG_TYPE_ACK_RESPONSE");
  }

  return("???");
}

/* *********************************************** */

void hexdump(char *buf, u_int len) {
  int i;
  
  for(i=0; i<len; i++) {
    if((i > 0) && ((i % 16) == 0)) printf("\n");
    printf("%02X ", buf[i] & 0xFF);
  }

  printf("\n");
}
