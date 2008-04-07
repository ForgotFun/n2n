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

#if defined(DEBUG)
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT          120
#else /* #if defined(DEBUG) */
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT           (60*5)
#endif /* #if defined(DEBUG) */

static u_int pkt_sent = 0;

/* *********************************************** */

static void help() {
  print_n2n_version();
  printf("supernode -l <listening port> [-v] [-h]\n");
  exit(0);
}

/* *********************************************** */

static struct peer_info *known_peers = NULL;

/* *********************************************** */

static void register_peer(struct n2n_packet_header *hdr,
			  struct peer_addr *sender,
			  int sock_fd, u_char is_udp_socket) {
  struct peer_info *scan = known_peers;
  char buf[32], buf1[32], mac_buf[32];

  while(scan != NULL) {
    if((strcmp(scan->community_name, hdr->community_name) == 0)
       && (memcmp(&scan->mac_addr, hdr->src_mac, 6) == 0)) {

      scan->last_seen = time(NULL);
      if ( ( 0 != memcmp(&scan->public_ip, sender, sizeof(struct peer_addr)) ) ||
             ( 0 != memcmp(&scan->private_ip, &hdr->private_ip, sizeof(struct peer_addr)) ) ) 
      {
        /* Something is actually different. */
        memcpy(&scan->public_ip, sender, sizeof(struct peer_addr));
        memcpy(&scan->private_ip, &hdr->private_ip, sizeof(struct peer_addr));

        /* Overwrite existing peer */
        traceEvent(TRACE_NORMAL, "Re-registered node [public_ip=%s:%d][private_ip=%s:%d][mac=%s][community=%s]",
                   intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
                   ntohs(scan->public_ip.port),
                   intoa(ntohl(scan->private_ip.addr_type.v4_addr), buf1, sizeof(buf1)),
                   ntohs(scan->private_ip.port),
                   macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
                   scan->community_name);
      }
      
      return; /* Found the registration entry so stop. */
    }

    scan = scan->next;
  }

  /* FIX mettere un limite alla lista dei peer */

  scan = (struct peer_info*)calloc(1, sizeof(struct peer_info));
  memcpy(scan->community_name, hdr->community_name, COMMUNITY_LEN);
  memcpy(&scan->public_ip, sender, sizeof(struct peer_addr));
  memcpy(&scan->private_ip, &hdr->private_ip, sizeof(struct peer_addr));
  memcpy(&scan->mac_addr, hdr->src_mac, 6);
  scan->last_seen = time(NULL); // FIX aggiungere un timeout
  scan->next = known_peers;
  scan->sock_fd = sock_fd, scan->is_udp_socket = is_udp_socket;
  known_peers = scan;

  traceEvent(TRACE_NORMAL, "Registered new node [public_ip=%s:%d][private_ip=%s:%d][mac=%s][community=%s]",
	     intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
	     ntohs(scan->public_ip.port),
	     intoa(ntohl(scan->private_ip.addr_type.v4_addr), buf1, sizeof(buf1)),
	     ntohs(scan->private_ip.port),
	     macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
	     scan->community_name);
}

/* *********************************************** */

static void deregister_peer(struct n2n_packet_header *hdr,
			    struct peer_addr *sender) {
  struct peer_info *scan = known_peers, *prev = NULL;
  char buf[32], buf1[32];

  while(scan != NULL) {
    if((strcmp(scan->community_name, hdr->community_name) == 0)
       && (memcmp(&scan->mac_addr, hdr->src_mac, 6) == 0)) {
      /* Overwrite existing peer */
      if(prev == NULL)
	known_peers = scan->next;
      else
	prev->next = scan->next;

      traceEvent(TRACE_INFO, "Degistered node [public_ip=%s:%d][private_ip=%s:%d]",
		 intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
		 ntohs(scan->public_ip.port),
		 intoa(ntohl(scan->private_ip.addr_type.v4_addr), buf1, sizeof(buf1)),
		 ntohs(scan->private_ip.port));

      free(scan);
      return;
    }

    scan = scan->next;
  }

  traceEvent(TRACE_WARNING, "Unable to delete specified peer [%s:%d]",
	     intoa(ntohl(sender->addr_type.v4_addr), buf, sizeof(buf)),
	     ntohs(sender->port));
}

/* *********************************************** */

static void purge_expired_registrations() {
  static time_t last_purge = 0;
  time_t now = time(NULL);
  struct peer_info *scan, *prev;
  u_int num_reg = 0;

  if((now - last_purge) < PURGE_REGISTRATION_FREQUENCY) return;

  traceEvent(TRACE_INFO, "Purging old registrations");

  scan = known_peers, prev = NULL;
  while(scan != NULL) {
    char mac_buf[32], buf[32];

    if((now - scan->last_seen) > REGISTRATION_TIMEOUT) {
      struct peer_info *next = scan->next;

      if(prev == NULL)
	known_peers = next;
      else
	prev->next = next;

      traceEvent(TRACE_NORMAL, "Purged registration for host [%s:%d][mac=%s][last seen %d sec ago]",
		 intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
		 ntohs(scan->public_ip.port),
		 macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
		 (now - scan->last_seen));

      free(scan);
      scan = next;
    } else {
      num_reg++;

      traceEvent(TRACE_INFO, "== [%d] Registration [ip=%s:%d][mac=%s][community=%s][last seen %d sec ago]",
		 num_reg, intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
                 ntohs(scan->public_ip.port),
		 macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
		 scan->community_name, (now - scan->last_seen));

      prev = scan;
      scan = scan->next;
    }
  }

  last_purge = now;
  traceEvent(TRACE_INFO, "%d active registrations", num_reg);
}

/* *********************************************** */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "listening-port",  required_argument, NULL, 'l' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/* *********************************************** */

static void handle_packet(char *packet, u_int packet_len, 
			  struct peer_addr *sender,
			  int sock_fd, u_char is_udp_socket) {
  char buf[32];

  traceEvent(TRACE_INFO, "Received message from node [%s:%d]",
	     intoa(ntohl(sender->addr_type.v4_addr), buf, sizeof(buf)),
	     ntohs(sender->port));

  if(packet_len < N2N_PKT_HDR_SIZE)
    traceEvent(TRACE_WARNING, "Received packet too short [len=%d]\n", packet_len);
  else {
    struct n2n_packet_header hdr_storage;
    struct n2n_packet_header *hdr = &hdr_storage;

    unmarshall_n2n_packet_header( hdr, (u_int8_t *)packet );

    if(hdr->version != N2N_VERSION) {
      traceEvent(TRACE_WARNING,
		 "Received packet with unknown protocol version (%d): discarded\n",
		 hdr->version);
      return;
    }

    if(hdr->msg_type == MSG_TYPE_REGISTER) 
    {
        register_peer(hdr, sender, sock_fd, is_udp_socket);
    }
    else if(hdr->msg_type == MSG_TYPE_DEREGISTER) {
      deregister_peer(hdr, sender);
    } else if(hdr->msg_type == MSG_TYPE_PACKET) {
      /* This is a packet to route */
      u_int8_t is_dst_broad_multi_cast;
      struct peer_info *scan;
      u_char packet_sent = 0;

      hdr->ttl++; /* FIX discard packets with a high TTL */
      is_dst_broad_multi_cast = is_multi_broadcast(hdr->dst_mac);

      /* Put the original packet sender (public) address */
      memcpy(&hdr->public_ip, sender, sizeof(struct peer_addr));
      hdr->sent_by_supernode = 1;

      scan = known_peers;
      while(scan != NULL) {
	if((strcmp(scan->community_name, hdr->community_name) == 0)
	   && (is_dst_broad_multi_cast || (memcmp(scan->mac_addr, hdr->dst_mac, 6) == 0))
	   && (memcmp(sender, &scan->public_ip, sizeof(struct peer_addr)) /* No L3 self-send */)
	   && (memcmp(hdr->dst_mac, hdr->src_mac, 6) /* No L2 self-send */)) {
	  size_t len = packet_len;
          
          marshall_n2n_packet_header( (u_int8_t *)packet, hdr );
	  int data_sent_len = send_data(scan->sock_fd, scan->is_udp_socket, packet, &len, &scan->public_ip, 0);

	  if(data_sent_len != len)
	    traceEvent(TRACE_WARNING, "sendto() [sent=%d][attempted_to_send=%d] [%s]\n",
		       data_sent_len, len, strerror(errno));
	  else {
	    char buf1[32];

	    packet_sent = 1, pkt_sent++;
	    traceEvent(TRACE_INFO, "Sent %smessage to remote node [%s:%d][mac=%s]",
		       is_dst_broad_multi_cast ? "broadcast " : "",
		       intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
		       ntohs(scan->public_ip.port),
		       macaddr_str(scan->mac_addr, buf1, sizeof(buf1)));
	  }

	  // if(!is_dst_broad_multi_cast) break;
	}

	scan = scan->next;
      } /* while */

      if(!packet_sent) {
	traceEvent(TRACE_INFO, "Unable to find a recipient for the received packet [mac=%s]",
		   macaddr_str(hdr->dst_mac, buf, sizeof(buf)));
      }
    } else {
      traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored\n",
		 hdr->msg_type);
    }
  }
}

/* *********************************************** */

static
#ifdef WIN32
DWORD tcpReadThread(LPVOID lpArg)
#else
  void* tcpReadThread(void *lpArg)
#endif
{
  int sock_fd = (int)lpArg;
  char c[1600];
  int new_line = 0;

  traceEvent(TRACE_NORMAL, "Handling sock_fd %d", sock_fd);

  while(1) {
    int rc;

    if((rc = recv(sock_fd, c, 2, 0)) > 0) {
      if((c[0] == '\r') && (c[1] == '\n')) {
	if(!new_line)
	  new_line = 1;
	else
	  break; /* Double \r\n\r\n, the http header is over */
      } else
	printf("%c%c [%d][%d] ", c[0], c[1], c[0], c[1]); fflush(stdout);
    } else {
      traceEvent(TRACE_NORMAL, "recv() error [rc=%d][%s]", rc, strerror(errno));
      break;
    }
  }

  /* Beginning of n2n protocol over TCP */
  c[5] = 0;

  while(1) {
    int rc;

    // FIX: add select
    if((rc = recv(sock_fd, c, 4, 0)) == 4) {
      int len = atoi(c);
      socklen_t from_len = sizeof(struct sockaddr_in );
      struct sockaddr_in from;

      /* Check packet length */
      if((len <= 0) || (len >= 1600)) break;
      rc = recvfrom(sock_fd, c, len, 0, (struct sockaddr*)&from, &from_len);

      if((rc <= 0) || (rc != len))
	break;
      else {
	struct peer_addr _from;

	sockaddr_in2peer_addr(&from, &_from);
	handle_packet(c, len, &_from, sock_fd, 0 /* tcp */);
      }
    } else
      break;
  }

  close(sock_fd);
  return(NULL);
}


/* *********************************************** */

static void startTcpReadThread(int sock_fd) {
#ifdef WIN32
  HANDLE hThread;
  DWORD dwThreadId;

  hThread = CreateThread(NULL, /* no security attributes */
			 0,    /* use default stack size */
			 (LPTHREAD_START_ROUTINE)tcpReadThread, /* thread function */
			 (void*)sock_fd, /* argument to thread function */
			 0,              /* use default creation flags */
			 &dwThreadId);   /* returns the thread identifier */
#else
  int rc;
  pthread_t threadId;

  rc = pthread_create(&threadId, NULL, tcpReadThread, (void*)sock_fd);
#endif
}

/* *********************************************** */

int main(int argc, char* argv[]) {
  int opt, local_port = 0;
  int udp_sock_fd, tcp_sock_fd;

  optarg = NULL;
  while((opt = getopt_long(argc, argv, "l:vh", long_options, NULL)) != EOF) {
    switch (opt) {
    case 'l': /* local-port */
      local_port = atoi(optarg);
      break;
    case 'h': /* help */
      help();
      break;
    case 'v': /* verbose */
      traceLevel = 3;
      break;
    }
  }

  if(!(local_port))
    help();

  if(init_n2n( NULL, 0) < 0) return(-1);

  udp_sock_fd = open_socket(local_port, 1, 0);
  if(udp_sock_fd < 0) return(-1);

  tcp_sock_fd = open_socket(local_port, 0, 1);
  if(tcp_sock_fd < 0) return(-1);

  traceEvent(TRACE_NORMAL, "Supernode ready: listening on port %d [TCP/UDP]", local_port);

  while(1) {
    int rc, max_sock;
    fd_set socket_mask;
    struct timeval wait_time;

    FD_ZERO(&socket_mask);
    max_sock = max(udp_sock_fd, tcp_sock_fd);
    FD_SET(udp_sock_fd, &socket_mask);
    FD_SET(tcp_sock_fd, &socket_mask);

    wait_time.tv_sec = 10; wait_time.tv_usec = 0;
    rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);

    if(rc > 0) {
      if(FD_ISSET(udp_sock_fd, &socket_mask)) {
	char packet[2048];
	size_t len;
	struct peer_addr sender;
	u_int8_t discarded_pkt;
	struct n2n_packet_header hdr;

	len = receive_data(udp_sock_fd, 1, packet, sizeof(packet), &sender, &discarded_pkt, NULL, 0, &hdr);

	if(len <= 0)
	  traceEvent(TRACE_WARNING, "recvfrom()=%d [%s]\n", len, strerror(errno));
	else {
	  handle_packet(packet, len, &sender, udp_sock_fd, 1);
	}
      } else if(FD_ISSET(tcp_sock_fd, &socket_mask)) {
	struct sockaddr from;
	int from_len = sizeof(from);
	int new_sock = accept(tcp_sock_fd, (struct sockaddr*)&from,
			      (socklen_t*)&from_len);

	if(new_sock < 0) {
	  traceEvent(TRACE_WARNING, "TCP connection accept() failed [%s]\n", strerror(errno));
	} else {
	  startTcpReadThread(new_sock);
	}
      }
    }

    purge_expired_registrations();
  } /* while */

  close(udp_sock_fd);
  close(tcp_sock_fd);

  return(0);
}
