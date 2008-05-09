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
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * Richard Andrews <bbmaj7@yahoo.com.au>
 * Don Bindner <don.bindner@gmail.com>
 *
 */

#include "n2n.h"
#include <assert.h>

/** Time between logging system STATUS messages */
#define STATUS_UPDATE_INTERVAL (30 * 60) /*secs*/

static struct peer_addr supernode;
static char *community_name = NULL, is_udp_sock = 1;
u_int pkt_sent = 0;
static tuntap_dev device;
static int edge_sock_fd, allow_routing = 0;

static void send_packet2net(int sock_fd, u_char is_udp_socket,
			    char *decrypted_msg, size_t len,
			    u_char allow_routed_packets); /* Forward */

char *encrypt_key = NULL;

/* *********************************************** */

static void readFromIPSocket();

static void help() {
  print_n2n_version();

  printf("edge "
#ifdef __linux__
	 "-d <tun device> "
#endif
	 "-a <tun IP address> "
	 "-c <community> "
	 "[-k <encrypt key>] "
	 "[-u <uid> -g <gid>]"
	 "[-m <MAC address>]"
	 "\n"
	 "-l <supernode host:port> "
	 "[-p <local port>] "
	 "[-t] [-r] [-v] [-h]\n\n");

#ifdef __linux__
  printf("-d <tun device>          | tun device name\n");
#endif

  printf("-a <tun IP address>      | n2n IP address\n");
  printf("-c <community>           | n2n community name\n");
  printf("-k <encrypt key>         | Encryption key (ASCII) - also N2N_KEY=<encrypt key>\n");
  printf("-l <supernode host:port> | Supernode IP:port\n");
  printf("-p <local port>          | Local port used for connecting to supernode\n");
  printf("-u <UID>                 | User ID (numeric) to use when privileges are dropped\n");
  printf("-g <GID>                 | Group ID (numeric) to use when privileges are dropped\n");
  printf("-m <MAC address>         | Choose a MAC address for the TAP interface, eg. -m 01:02:03:04:05:06\n");
  printf("-t                       | Use http tunneling (experimental)\n");
  printf("-r                       | Enable packet forwarding through n2n community\n");
  printf("-v                       | Verbose\n");

  printf("\nEnvironment variables:\n");
  printf("  N2N_KEY                | Encryption key (ASCII)\n" ); 

  exit(0);
}

/* *********************************************** */

static struct peer_info *known_peers = NULL;
static struct peer_info *pending_peers = NULL;
static time_t last_register = 0;


/* *********************************************** */

static void send_register(int sock, u_char is_udp_socket,
			  const struct peer_addr *remote_peer, 
			  u_char is_ack) {
  struct n2n_packet_header hdr;
  char pkt[N2N_PKT_HDR_SIZE];
  size_t len = sizeof(hdr);
  ipstr_t ip_buf;

  fill_standard_header_fields(sock, is_udp_socket, &hdr, (char*)device.mac_addr);
  hdr.sent_by_supernode = 0;
  hdr.msg_type = (is_ack == 0) ? MSG_TYPE_REGISTER : MSG_TYPE_REGISTER_ACK;
  memcpy(hdr.community_name, community_name, COMMUNITY_LEN);

  marshall_n2n_packet_header( (u_int8_t *)pkt, &hdr );
  send_packet(sock, is_udp_socket, pkt, &len, remote_peer, 1);

  traceEvent(TRACE_INFO, "Sent %s message to %s:%d",
             ((hdr.msg_type==MSG_TYPE_REGISTER)?"MSG_TYPE_REGISTER":"MSG_TYPE_REGISTER_ACK"),
	     intoa(ntohl(remote_peer->addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
	     ntohs(remote_peer->port));
}

/* *********************************************** */

static void send_deregister(int sock, u_char is_udp_socket,
			    struct peer_addr *remote_peer) {
  struct n2n_packet_header hdr;
  char pkt[N2N_PKT_HDR_SIZE];
  size_t len = sizeof(hdr);

  fill_standard_header_fields(sock, is_udp_socket,&hdr, (char*)device.mac_addr);
  hdr.sent_by_supernode = 0;
  hdr.msg_type = MSG_TYPE_DEREGISTER;
  memcpy(hdr.community_name, community_name, COMMUNITY_LEN);

  marshall_n2n_packet_header( (u_int8_t *)pkt, &hdr );
  send_packet(sock, is_udp_socket, pkt, &len, remote_peer, 1);
}

/* *********************************************** */

static void update_peer_address(int sock_fd, u_char is_udp_socket, 
                                const struct n2n_packet_header * hdr, 
                                time_t when);
void trace_registrations( struct peer_info * scan );
int is_ip6_discovery( const void * buf, size_t bufsize );
struct peer_info * find_peer_by_mac( struct peer_info * list,
                                     const char * mac );
void peer_list_add( struct peer_info * * list, 
                    struct peer_info * new );
size_t peer_list_size( const struct peer_info * list );
void check_peer( int sock, 
                 u_char is_udp_socket, 
                 const struct n2n_packet_header * hdr );
void try_send_register( int sock, 
                        u_char is_up_socket, 
                        const struct n2n_packet_header * hdr );
void set_peer_operational( const struct n2n_packet_header * hdr );



/** Start the registration process.
 *
 *  If the peer is already in pending_peers, ignore the request.
 *  If not in pending_peers, add it and send a REGISTER.
 *
 *  If hdr is for a direct peer-to-peer packet, try to register back to sender
 *  even if the MAC is in pending_peers. This is because an incident direct
 *  packet indicates that peer-to-peer exchange should work so more aggressive
 *  registration can be permitted (once per incoming packet) as this should only
 *  last for a small number of packets..
 *
 *  Called from the main loop when Rx a packet for our device mac.
 */
void try_send_register( int sock, 
                        u_char is_udp_socket, 
                        const struct n2n_packet_header * hdr )
{
    ipstr_t ip_buf;

    /* REVISIT: purge of pending_peers not yet done. */
    struct peer_info * scan = find_peer_by_mac( pending_peers, hdr->src_mac );

    if ( NULL == scan )
    {
        scan = calloc( 1, sizeof( struct peer_info ) );
        
        memcpy(scan->mac_addr, hdr->src_mac, 6);
        scan->public_ip = hdr->public_ip;
        scan->last_seen = time(NULL); /* Don't change this it marks the pending peer for removal. */

        peer_list_add( &pending_peers, scan );

        traceEvent( TRACE_NORMAL, "Pending peers list size=%ld",
                    peer_list_size( pending_peers ) );

        traceEvent( TRACE_NORMAL, "Sending REGISTER request to %s:%d",
                    intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                    ntohs(scan->public_ip.port));

        send_register(sock, is_udp_socket,
                      &(scan->public_ip), 
                      0 /* is not ACK */ );

        /* pending_peers now owns scan. */
    }
    else
    {
        /* scan already in pending_peers. */

        if ( 0 == hdr->sent_by_supernode )
        {
            /* over-write supernode-based socket with direct socket. */
            scan->public_ip = hdr->public_ip;

            traceEvent( TRACE_NORMAL, "Sending additional REGISTER request to %s:%d",
                        intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                        ntohs(scan->public_ip.port));


            send_register(sock, is_udp_socket,
                          &(scan->public_ip), 
                          0 /* is not ACK */ );
        }
    }
}


/** Update the last_seen time for this peer, or get registered. */
void check_peer( int sock, 
                 u_char is_udp_socket, 
                 const struct n2n_packet_header * hdr )
{
    struct peer_info * scan = find_peer_by_mac( known_peers, hdr->src_mac );
    
    if ( NULL == scan )
    {
        /* Not in known_peers - start the REGISTER process. */
        try_send_register( sock, is_udp_socket, hdr );
    }
    else
    {
        /* Already in known_peers. */
        update_peer_address( edge_sock_fd, is_udp_sock, hdr, time(NULL) );
    }
}


/* Move the peer from the pending_peers list to the known_peers lists. 
 *
 * peer must be a pointer to an element of the pending_peers list.
 *
 * Called by main loop when Rx a REGISTER_ACK.
 */
void set_peer_operational( const struct n2n_packet_header * hdr )
{
    struct peer_info * prev = NULL;
    struct peer_info * scan;
    macstr_t mac_buf;
    ipstr_t ip_buf;

    scan=pending_peers;

    while ( NULL != scan )
    {
        if ( 0 != memcmp( scan->mac_addr, hdr->dst_mac, 6 ) )
        {
            break; /* found. */
        }

        prev = scan;
        scan = scan->next;
    }

    if ( scan )
    {

        /* Remove scan from pending_peers. */
        if ( prev )
        {
            prev->next = scan->next;
        }
        else
        {
            pending_peers = scan->next;
        }

        /* Add scan to known_peers. */
        scan->next = known_peers;
        known_peers = scan;

        scan->public_ip = hdr->public_ip;

        traceEvent(TRACE_INFO, "=== new peer [mac=%s][socket=%s:%d]",
                   macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
                   intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                   ntohs(scan->public_ip.port));

        traceEvent( TRACE_NORMAL, "Pending peers list size=%ld",
                    peer_list_size( pending_peers ) );

        traceEvent( TRACE_NORMAL, "Operational peers list size=%ld",
                    peer_list_size( known_peers ) );


        scan->last_seen = time(NULL);
    }
    else
    {
        traceEvent( TRACE_WARNING, "Failed to find sender in pending_peers." );
    }
}


void trace_registrations( struct peer_info * scan )
{
    macstr_t mac_buf;
    ipstr_t ip_buf;

    while ( scan )
    {
        traceEvent(TRACE_INFO, "=== peer [mac=%s][socket=%s:%d]",
                   macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
                   intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                   ntohs(scan->public_ip.port));

        scan = scan->next;
    }

}

u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


/** Keep the known_peers list straight.
 *
 *  Ignore broadcast L2 packets, and packets with invalid public_ip.
 *  If the dst_mac is in known_peers make sure the entry is correct:
 *  - if the public_ip socket has changed, erase the entry
 *  - if the same, update its last_seen = when
 */
static void update_peer_address(int sock_fd, u_char is_udp_socket, 
                                const struct n2n_packet_header * hdr, 
                                time_t when) 
{
    ipstr_t ip_buf;
    struct peer_info *scan = known_peers;
    struct peer_info *prev = NULL; /* use to remove bad registrations. */

    if ( 0 == hdr->public_ip.addr_type.v4_addr ) 
    {
        /* Not to be registered. */
        return;
    }

    if ( 0 == memcmp( hdr->dst_mac, broadcast_mac, 6 ) )
    {
        /* Not to be registered. */
        return;
    }


    while(scan != NULL) 
    {
        if(memcmp(hdr->dst_mac, scan->mac_addr, 6) == 0) 
        {
            break;
        }

        prev = scan;
        scan = scan->next;
    }

    if ( NULL == scan )
    {
        /* Not in known_peers. */
        return;
    }

    if ( 0 != memcmp( &(scan->public_ip), &(hdr->public_ip), sizeof(struct peer_addr))) 
    {
        if ( 0 == hdr->sent_by_supernode )
        {
            traceEvent( TRACE_NORMAL, "Peer changed public socket, Was %s:%d",
                        intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                        ntohs(hdr->public_ip.port));

            /* The peer has changed public socket. It can no longer be assumed to be reachable. */
            /* Remove the peer. */
            if ( NULL == prev )
            {
                /* scan was head of list */
                known_peers = scan->next;
            }
            else
            {
                prev->next = scan->next;
            }
            free(scan);
        
            try_send_register( sock_fd, is_udp_socket, hdr );
        }
        else
        {
            /* Don't worry about what the supernode reports, it could be seeing a different socket. */
        }
    }
    else
    {
        /* Found and unchanged. */
        scan->last_seen = when;
    }
}



#if defined(DUMMY_ID_00001) /* Disabled waiting for config option to enable it */
/* *********************************************** */
static char gratuitous_arp[] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* Dest mac */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x08, 0x06, /* ARP */
  0x00, 0x01, /* Ethernet */
  0x08, 0x00, /* IP */
  0x06, /* Hw Size */
  0x04, /* Protocol Size */
  0x00, 0x01, /* ARP Request */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Src mac */
  0x00, 0x00, 0x00, 0x00, /* Src IP */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Target mac */
  0x00, 0x00, 0x00, 0x00 /* Target IP */
};

static int build_gratuitous_arp(char *buffer, u_short buffer_len) {
  if(buffer_len < sizeof(gratuitous_arp)) return(-1);

  memcpy(buffer, gratuitous_arp, sizeof(gratuitous_arp));
  memcpy(&buffer[6], device.mac_addr, 6);
  memcpy(&buffer[22], device.mac_addr, 6);
  memcpy(&buffer[28], &device.ip_addr, 4);

  /* REVISIT: BbMaj7 - use a real netmask here. This is valid only by accident
   * for /24 IPv4 networks. */
  buffer[31] = 0xFF; /* Use a faked broadcast address */
  memcpy(&buffer[38], &device.ip_addr, 4);
  return(sizeof(gratuitous_arp));
}

/** Called from update_registrations to periodically send gratuitous ARP
 * broadcasts. */
static void send_grat_arps(int sock_fd, u_char is_udp_socket) {
  char buffer[48];
  size_t len;

  traceEvent(TRACE_NORMAL, "Sending gratuitous ARP...");
  len = build_gratuitous_arp(buffer, sizeof(buffer));
  send_packet2net(sock_fd, is_udp_socket, buffer, len, allow_routing);
  send_packet2net(sock_fd, is_udp_socket, buffer, len, allow_routing); /* Two is better than one :-) */
}
#endif /* #if defined(DUMMY_ID_00001) */



/* *********************************************** */

/** @brief Check to see if we should re-register with our peers and the
 *         supernode.
 *
 *  This is periodically called by the main loop. The list of registrations is
 *  not modified. Registration packets may be sent.
 */
static void update_registrations(int sock_fd, u_char is_udp_socket) {
  /* REVISIT: BbMaj7: have shorter timeout to REGISTER to supernode if this has
   * not yet succeeded. */

  if(time(NULL) < (last_register+REGISTER_FREQUENCY)) return; /* Too early */

  traceEvent(TRACE_NORMAL, "Registering with supernode");
  send_register(sock_fd, is_udp_socket, &supernode, 0); /* Register with supernode */

  /* REVISIT: turn-on gratuitous ARP with config option. */
  /* send_grat_arps(sock_fd, is_udp_sock); */

  last_register = time(NULL);
}

/* ***************************************************** */

/** Find the peer entry in list with mac_addr equal to mac.
 *
 *  Does not modify the list.
 *
 *  @return NULL if not found; otherwise pointer to peer entry.
 */
struct peer_info * find_peer_by_mac( struct peer_info * list,
                                     const char * mac )
{
    while(list != NULL) 
    {
        if( 0 == memcmp(mac, list->mac_addr, 6) ) 
        {
            return list;
        }
        list = list->next;
    }

    return NULL;
}


/** Return the number of elements in the list.
 *
 */
size_t peer_list_size( const struct peer_info * list )
{
    size_t retval=0;

    while ( list )
    {
        ++retval;
        list = list->next;
    }

    return retval;
}

/** Add new to the head of list. If list is NULL; create it.
 *
 *  The item new is added to the head of the list. New is modified during
 *  insertion. list takes ownership of new.
 */
void peer_list_add( struct peer_info * * list, 
                    struct peer_info * new )
{
    new->next = *list;
    new->last_seen = time(NULL);
    *list = new;
}


static int find_peer_destination(const u_char *mac_address, struct peer_addr *destination) {
  const struct peer_info *scan = known_peers;
  macstr_t mac_buf;
  ipstr_t ip_buf;
  int retval=0;

  traceEvent(TRACE_INFO, "Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
	     mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
	     mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

  while(scan != NULL) {
    traceEvent(TRACE_INFO, "Evaluating peer [MAC=%02X:%02X:%02X:%02X:%02X:%02X][ip=%s:%d]",
	       scan->mac_addr[0] & 0xFF, scan->mac_addr[1] & 0xFF, scan->mac_addr[2] & 0xFF,
	       scan->mac_addr[3] & 0xFF, scan->mac_addr[4] & 0xFF, scan->mac_addr[5] & 0xFF,
	       intoa(ntohl(scan->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
	       ntohs(scan->public_ip.port));
    
    if((scan->last_seen > 0) &&
       (memcmp(mac_address, scan->mac_addr, 6) == 0)) 
    {
        memcpy(destination, &scan->public_ip, sizeof(struct sockaddr_in));
        retval=1;
        break;
    }
    scan = scan->next;
  }

  if ( 0 == retval )
  {
      memcpy(destination, &supernode, sizeof(struct sockaddr_in));
  }

  traceEvent(TRACE_INFO, "find_peer_address(%s) -> [socket=%s:%d]",
             macaddr_str( (char *)mac_address, mac_buf, sizeof(mac_buf)),
             intoa(ntohl(destination->addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
             ntohs(destination->port));



  return retval;
}

/* *********************************************** */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "supernode-list",  required_argument, NULL, 'l' },
  { "tun-device",      required_argument, NULL, 'd' },
  { "euid",            required_argument, NULL, 'u' },
  { "egid",            required_argument, NULL, 'g' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/* ***************************************************** */


/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
static void send_packet2net(int sock_fd, u_char is_udp_socket,
			    char *decrypted_msg, size_t len,
			    u_char allow_routed_packets) {
  ipstr_t ip_buf;
  char packet[2048];
  int data_sent_len;
  struct n2n_packet_header hdr;
  struct peer_addr destination;
  macstr_t mac_buf;
  macstr_t mac2_buf;
  struct ether_header *eh = (struct ether_header*)decrypted_msg;

  /* Discard IP packets that are not originated by this hosts */
  if(!allow_routed_packets) {
    if(ntohs(eh->ether_type) == 0x0800) {

      /* Note: all elements of the_ip are in network order */
      struct ip *the_ip = (struct ip*)(decrypted_msg+sizeof(struct ether_header));

      if(the_ip->ip_src.s_addr != device.ip_addr) {
	/* This is a packet that needs to be routed */
	traceEvent(TRACE_INFO, "Discarding routed packet");
	return;
      } else {
	/* This packet is originated by us */
	/* traceEvent(TRACE_INFO, "Sending non-routed packet"); */
      }
    }
  }

  /* Encrypt "decrypted_msg" into the second half of the n2n packet. */
  len = TwoFishEncryptRaw((u_int8_t *)decrypted_msg,
			  (u_int8_t *)&packet[N2N_PKT_HDR_SIZE], len, tf);

  /* Add the n2n header to the start of the n2n packet. */
  fill_standard_header_fields(sock_fd, is_udp_socket,
			      &hdr, (char*)device.mac_addr);
  hdr.msg_type = MSG_TYPE_PACKET;
  hdr.sent_by_supernode = 0;
  memcpy(hdr.community_name, community_name, COMMUNITY_LEN);
  memcpy(hdr.dst_mac, decrypted_msg, 6);

  marshall_n2n_packet_header( (u_int8_t *)packet, &hdr );

  len += N2N_PKT_HDR_SIZE;

  if(find_peer_destination(eh->ether_dhost, &destination))
    traceEvent(TRACE_INFO, "** Going direct [dst_mac=%s][dest=%s:%d]",
	       macaddr_str((char*)eh->ether_dhost, mac_buf, sizeof(mac_buf)),
	       intoa(ntohl(destination.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
	       ntohs(destination.port));
  else
    traceEvent(TRACE_INFO, "   Going via supernode [src_mac=%s][dst_mac=%s]",
	       macaddr_str((char*)eh->ether_shost, mac_buf, sizeof(mac_buf)),
	       macaddr_str((char*)eh->ether_dhost, mac2_buf, sizeof(mac2_buf)));

  data_sent_len = reliable_sendto(sock_fd, is_udp_socket, packet, &len, &destination, 1);

  if(data_sent_len != len)
    traceEvent(TRACE_WARNING, "sendto() [sent=%d][attempted_to_send=%d] [%s]\n",
	       data_sent_len, len, strerror(errno));
  else {
    pkt_sent++;
    traceEvent(TRACE_INFO, "Sent %d byte MSG_TYPE_PACKET ok", data_sent_len);
  }
}

/* ***************************************************** */

/** Destination MAC 33:33:0:00:00:00 - 33:33:FF:FF:FF:FF is reserved for IPv6
 * neighbour discovery. 
 */
int is_ip6_discovery( const void * buf, size_t bufsize )
{
    int retval = 0;
    if ( bufsize >= sizeof(struct ether_header) )
    {
        struct ether_header *eh = (struct ether_header*)buf;
        if ( (0x33 == eh->ether_dhost[0]) &&
             (0x33 == eh->ether_dhost[1]) )
        {
            retval = 1; /* This is an IPv6 neighbour discovery packet. */
        }
    }
    return retval;
}


/* ***************************************************** */

/*
 * Return: 0 = ok, -1 = invalid packet
 *
 */
static int check_received_packet(tuntap_dev *dev, char *pkt,
				 u_int pkt_len, u_char allow_routed_packets) {

  if(pkt_len == 42) {
    /* ARP */
    if((pkt[12] != 0x08) || (pkt[13] != 0x06)) return(0); /* No ARP */
    if((pkt[20] != 0x00) || (pkt[21] != 0x02)) return(0); /* No ARP Reply */
    if(memcmp(&pkt[28], &device.ip_addr, 4))   return(0); /* This is not me */

    if(memcmp(dev->mac_addr, &pkt[22], 6) == 0) {
      traceEvent(TRACE_WARNING, "Bounced packet received: supernode bug?");
      return(0);
    }

    traceEvent(TRACE_ERROR, "Duplicate address found. Your IP is used by MAC %02X:%02X:%02X:%02X:%02X:%02X",
	       pkt[22+0] & 0xFF, pkt[22+1] & 0xFF, pkt[22+2] & 0xFF,
	       pkt[22+3] & 0xFF, pkt[22+4] & 0xFF, pkt[22+5] & 0xFF);
    exit(0);
  } else if(pkt_len > 32 /* IP + Ethernet */) {
    /* Check if this packet is for us or if it's routed */
    struct ether_header *eh = (struct ether_header*)pkt;

    if(ntohs(eh->ether_type) == 0x0800) {

      /* Note: all elements of the_ip are in network order */
      struct ip *the_ip = (struct ip*)(pkt+sizeof(struct ether_header));

      if((the_ip->ip_dst.s_addr != device.ip_addr)
	 && ((the_ip->ip_dst.s_addr & device.device_mask) != (device.ip_addr & device.device_mask))) /* Not a broadcast */
	{
          ipstr_t ip_buf;
          ipstr_t ip_buf2;

	  /* This is a packet that needs to be routed */
	  traceEvent(TRACE_INFO, "Discarding routed packet [rcvd=%s][expected=%s]",
		     intoa(ntohl(the_ip->ip_dst.s_addr), ip_buf, sizeof(ip_buf)),
		     intoa(ntohl(device.ip_addr), ip_buf2, sizeof(ip_buf2)));
	} else {
	/* This packet is for us */

	/* traceEvent(TRACE_INFO, "Received non-routed packet"); */
	return(0);
      }
    } else
      return(0);
  } else {
    traceEvent(TRACE_INFO, "Packet too short (%d bytes): discarded", pkt_len);
  }

  return(-1);
}

/* ***************************************************** */

/** Read a single packet from the TAP interface, process it and write out the
 *  corresponding packet to the cooked socket. 
 *
 *  REVISIT: fails if more than one packet is waiting to be read.
 */
static void readFromTAPSocket()
{
    /* tun -> remote */
    u_char decrypted_msg[2048];
    size_t len;

    len = tuntap_read(&device, decrypted_msg, sizeof(decrypted_msg));

    if((len <= 0) || (len > sizeof(decrypted_msg)))
        traceEvent(TRACE_WARNING, "read()=%d [%d/%s]\n",
                   len, errno, strerror(errno));
    else {
        traceEvent(TRACE_INFO, "### Rx L2 Msg (%d) tun -> network", len);

        if ( is_ip6_discovery( decrypted_msg, len ) ) {
            traceEvent(TRACE_WARNING, "Dropping unsupported IPv6 neighbour discovery packet");
        } else {
            send_packet2net(edge_sock_fd, is_udp_sock, (char*)decrypted_msg,
                            len, allow_routing);
        }
    }
}

/* ***************************************************** */


void readFromIPSocket()
{
    ipstr_t ip_buf;
    macstr_t mac_buf;
    char packet[2048], decrypted_msg[2048];
    size_t len;
    int data_sent_len;
    struct peer_addr sender;

    /* remote -> tun */
    u_int8_t discarded_pkt;
    struct n2n_packet_header hdr_storage;

    len = receive_data(edge_sock_fd, is_udp_sock, packet, sizeof(packet), &sender,
                       &discarded_pkt, (char*)device.mac_addr, 1, &hdr_storage);

    if(len <= 0) return;

    traceEvent(TRACE_INFO, "### Rx N2N Msg network -> tun");

    if(discarded_pkt) {
        traceEvent(TRACE_INFO, "Discarded incoming pkt");
    } else {
        if(len <= 0)
            traceEvent(TRACE_WARNING, "receive_data()=%d [%s]\n", len, strerror(errno));
        else {
            if(len < N2N_PKT_HDR_SIZE)
                traceEvent(TRACE_WARNING, "received packet too short [len=%d]\n", len);
            else {
                struct n2n_packet_header *hdr = &hdr_storage;

                traceEvent(TRACE_INFO, "Received packet from %s:%d",
                           intoa(ntohl(sender.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                           ntohs(sender.port));

                traceEvent(TRACE_INFO, "Received message [msg_type=%s] from %s [dst mac=%s]",
                           msg_type2str(hdr->msg_type),
                           hdr->sent_by_supernode ? "supernode" : "peer",
                           macaddr_str(hdr->dst_mac, mac_buf, sizeof(mac_buf)));

                if(hdr->version != N2N_VERSION) {
                    traceEvent(TRACE_WARNING,
                               "Received packet with unknown protocol version (%d): discarded\n",
                               hdr->version);
                    return;
                }

                /* FIX - Add IPv6 support */
                if(hdr->public_ip.addr_type.v4_addr == 0) {
                    hdr->public_ip.addr_type.v4_addr = sender.addr_type.v4_addr;
                    hdr->public_ip.port = sender.port;
                    hdr->public_ip.family = AF_INET;
                }

                if(strncmp(hdr->community_name, community_name, COMMUNITY_LEN) != 0) {
                    traceEvent(TRACE_WARNING, "Received packet with invalid community [expected=%s][received=%s]\n",
                               community_name, hdr->community_name);
                } else {
                    if(hdr->msg_type == MSG_TYPE_PACKET) {
                        if(memcmp(hdr->dst_mac, device.mac_addr, 6)
                           && (!is_multi_broadcast(hdr->dst_mac))) {
                            traceEvent(TRACE_WARNING, "Received packet with invalid mac address %s: discarded\n",
                                       macaddr_str(hdr->dst_mac, mac_buf, sizeof(mac_buf)));
                            return;
                        }

                        /* assert: the packet received is destined for device.mac_addr or broadcast MAC. */

                        len -= N2N_PKT_HDR_SIZE;

                        /* Decrypt message first */
                        len = TwoFishDecryptRaw((u_int8_t *)&packet[N2N_PKT_HDR_SIZE],
                                                (u_int8_t *)decrypted_msg, len, tf);

                        if(len > 0) {
                            if(check_received_packet(&device, decrypted_msg, len, allow_routing) == 0) {

                                if ( 0 == memcmp(hdr->dst_mac, device.mac_addr, 6) )
                                {
                                    check_peer( edge_sock_fd, is_udp_sock, hdr );
                                }

                                data_sent_len = tuntap_write(&device, (u_char*)decrypted_msg, len);

                                if(data_sent_len != len)
                                    traceEvent(TRACE_WARNING, "tuntap_write() [sent=%d][attempted_to_send=%d] [%s]\n",
                                               data_sent_len, len, strerror(errno));
                                else {
                                    /* Normal situation. */
                                    traceEvent(TRACE_INFO, "### Tx L2 Msg -> tun");
                                }
                            } else {
                                traceEvent(TRACE_WARNING, "Bad destination: message discarded");
                            }
                        }
                        /* else silently ignore empty packet. */

                    } else if(hdr->msg_type == MSG_TYPE_REGISTER) {
                        traceEvent(TRACE_INFO, "Received registration request from remote peer [ip=%s:%d]",
                                   intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                                   ntohs(hdr->public_ip.port));
                        if ( 0 == memcmp(hdr->dst_mac, device.mac_addr, 6) )
                        {
                            check_peer( edge_sock_fd, is_udp_sock, hdr );
                        }


                        send_register(edge_sock_fd, is_udp_sock, &hdr->public_ip, 1); /* Send ACK back */
                    } else if(hdr->msg_type == MSG_TYPE_REGISTER_ACK) {
                        traceEvent(TRACE_NORMAL, "Received registration ack from remote peer [ip=%s:%d]",
                                   intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
                                   ntohs(hdr->public_ip.port));

                        /* if ( 0 == memcmp(hdr->dst_mac, device.mac_addr, 6) ) */
                        {
                            /* Move from pending_peers to known_peers; ignore if not in pending. */
                            set_peer_operational( hdr );
                        }

                    } else {
                        traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored\n", hdr->msg_type);
                        return;
                    }
                }
            }
        }
    }
}


/* ***************************************************** */

int main(int argc, char* argv[]) {
  int opt, local_port = 0 /* any port */;
  char *tuntap_dev_name = "edge0";
  char *ip_addr = NULL;
  ipstr_t ip_buf;

  uid_t userid=0; /* root is the only guaranteed ID */
  gid_t groupid=0; /* root is the only guaranteed ID */

  size_t numPurged;
  time_t lastStatus=0;

  char * device_mac=NULL;

  if( getenv( "N2N_KEY" )) {
    encrypt_key = strdup( getenv( "N2N_KEY" ));
  }

#ifdef WIN32
  tuntap_dev_name = "";
#endif
  memset(&supernode, 0, sizeof(supernode));
  supernode.family = AF_INET;

  optarg = NULL;
  while((opt = getopt_long(argc, argv, "k:a:c:u:g:m:d:l:p:vhrt", long_options, NULL)) != EOF) {
    switch (opt) {
    case 'a':
      ip_addr = strdup(optarg);
      break;
    case 'c': /* community */
      community_name = strdup(optarg);
      if(strlen(community_name) > COMMUNITY_LEN)
	community_name[COMMUNITY_LEN] = '\0';
      break;
    case 'u': /* uid */
    {
        userid=atoi(optarg);
        break;
    }
    case 'g': /* uid */
    {
        groupid=atoi(optarg);
        break;
    }
    case 'm' : /* device_mac */
    {
        device_mac=strdup(optarg);
        break;
    }
    case 'k': /* encrypt key */
      encrypt_key = strdup(optarg);
      break;
    case 'r': /* enable packet routing across n2n endpoints */
      allow_routing = 1;
      break;
    case 'l': /* supernode-list */
      {
	char *supernode_host = strtok(optarg, ":");
	if(supernode_host) {
	  char *supernode_port = strtok(NULL, ":");

	  if(supernode_port) {
	    supernode.port = htons(atoi(supernode_port));
	    supernode.addr_type.v4_addr = inet_addr(supernode_host);
	  } else
	    traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l)");
	} else
	  traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l)");
      }
      break;
#ifdef __linux__
    case 'd': /* tun-device */
      tuntap_dev_name = strdup(optarg);
      break;
#endif
    case 't': /* Use HTTP tunneling */
      is_udp_sock = 0;
      break;
    case 'p':
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

  if(!(
#ifdef __linux__
       tuntap_dev_name &&
#endif
       community_name &&
       ip_addr &&
       (supernode.addr_type.v4_addr != 0) &&
       encrypt_key))
    help();

  /* If running suid root then we need to setuid before using the force. */
  setuid( 0 );
  /* setgid( 0 ); */

  if(tuntap_open(&device, tuntap_dev_name, ip_addr, "255.255.255.0", device_mac ) < 0)
    return(-1);

  if ( (userid != 0) || (groupid != 0 ) ) {
    traceEvent(TRACE_NORMAL, "Interface up. Dropping privileges to uid=%d, gid=%d", userid, groupid);

    /* Finished with the need for root privileges. Drop to unprivileged user. */
    setreuid( userid, userid );
    setregid( groupid, groupid );
  }

  traceEvent(TRACE_NORMAL, "Using supernode %s:%d",
	     intoa(ntohl(supernode.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
	     ntohs(supernode.port));
  
  if(local_port > 0)
    traceEvent(TRACE_NORMAL, "Binding to local port %d", local_port);
  
  if(init_n2n( (u_int8_t *)encrypt_key, strlen(encrypt_key) ) < 0) return(-1);
  edge_sock_fd = open_socket(local_port, is_udp_sock, 0);
  if(edge_sock_fd < 0) return(-1);

  if(!is_udp_sock) {
    int rc = connect_socket(edge_sock_fd, &supernode);

    if(rc == -1) {
      traceEvent(TRACE_WARNING, "Error while connecting to supernode\n");
      return(-1);
    }
  }

  update_registrations(edge_sock_fd, is_udp_sock);

  traceEvent(TRACE_NORMAL, "");
  traceEvent(TRACE_NORMAL, "Ready");


  /* Main loop
   *
   * select() is used to wait for input on either the TAP fd or the UDP/TCP
   * socket. When input is present the data is read and processed by either
   * readFromIPSocket() or readFromTAPSocket()
   */

  while(1) {
    int rc, max_sock;
    fd_set socket_mask;
    struct timeval wait_time;
    time_t nowTime;

    FD_ZERO(&socket_mask);
    FD_SET(edge_sock_fd, &socket_mask);
    FD_SET(device.fd, &socket_mask);
    max_sock = MAX( edge_sock_fd, device.fd );

    wait_time.tv_sec = SOCKET_TIMEOUT_INTERVAL_SECS; wait_time.tv_usec = 0;

    rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);
    nowTime=time(NULL);

    if(rc > 0) 
    {
        /* Any or all of the FDs could have input; check them all. */

        if(FD_ISSET(edge_sock_fd, &socket_mask)) 
        {
            /* Read a cooked socket from the internet socket. Writes on the TAP
             * socket. */
            readFromIPSocket();
        }

        if(FD_ISSET(device.fd, &socket_mask)) 
        {
            /* Read an ethernet frame from the TAP socket. Write on the IP
             * socket. */
            readFromTAPSocket();
        }
    }

    update_registrations(edge_sock_fd, is_udp_sock);

    numPurged =  purge_expired_registrations( &known_peers );
    numPurged += purge_expired_registrations( &pending_peers );
    if ( numPurged > 0 )
    {
        traceEvent( TRACE_NORMAL, "Peer removed: pending=%ld, operational=%ld",
                    peer_list_size( pending_peers ), peer_list_size( known_peers ) );
    }

    if ( ( nowTime - lastStatus ) > STATUS_UPDATE_INTERVAL )
    {
        lastStatus = nowTime;
        
        traceEvent( TRACE_NORMAL, "STATUS: pending=%ld, operational=%ld",
                    peer_list_size( pending_peers ), peer_list_size( known_peers ) );
    }
  } /* while */

  send_deregister(edge_sock_fd, is_udp_sock, &supernode);

  close(edge_sock_fd);
  tuntap_close(&device);

  return(0);
}


