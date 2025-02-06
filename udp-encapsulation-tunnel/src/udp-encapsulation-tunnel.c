#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Compatibility layer for musl/glibc differences */
#ifdef __GLIBC__
#define udp_source	source
#define udp_dest	dest
#define udp_len		len
#define udp_check	check
#define tcp_check	check
#define tcp_source	source
#define tcp_dest	dest
#else
#define udp_source	uh_sport
#define udp_dest	uh_dport
#define udp_len		uh_ulen
#define udp_check	uh_sum
#define tcp_check	th_sum
#define tcp_source	th_sport
#define tcp_dest	th_dport
#endif

#define BUFFER_SIZE	2048
/* TODO: can be more if there are options, check IHL */
#define IP_HEADER_LEN	20
#define UDP_HEADER_LEN	8
/* TODO: can be more if there are options, check len */
#define TCP_HEADER_LEN	20

/* Connection store entry structure - stores (IPv4 saddr, UDP sport, TCP sport)
 */
struct connection_store {
	/* Peer IPv4 address */
	struct in_addr ip_saddr;
	/* Peer UDP port */
	uint16_t udp_sport;
	/* Peer TCP port */
	uint16_t tcp_sport;
	/* TODO: avoid using a list (O(n)), use a HashMap (O(1)) */
	struct connection_store *next;
	/* TODO: store a timestamp: to be able to remove old entries, and handle
	 * conflicts: same IP + TCP port, but different UDP port
	 */
};

struct tunnel_config {
	/* TODO: typically called "interface" or "iface"? */
	char interface[IFNAMSIZ];
	uint16_t listen_port;
	char bind_interface[IFNAMSIZ];
	/* TODO: typically called "destination_port" or "dport"? */
	uint16_t endpoint_port;
	/* TODO: avoid using a list (O(n)), use a HashMap (O(1)) */
	struct connection_store *store;
};

/* TODO: for the hashmap, we could have optimisations on the structure, because
 * the number of clients (IP addr + UDP port) should be limited, while the
 * number of TCP connections can be important. We could then store a hashmap of
 * IP address, and each one would have a hashmap of TCP ports. (A list of UDP
 * ports could be used per IP address: if there is only one item, no need to
 * find the corresponding TCP connection. But still needed to store them in case
 * another client is added later)
 */

/* Store connection information (IPv4 saddr, UDP sport, TCP sport) */
static void store_connection(struct tunnel_config *config, struct in_addr saddr,
			     uint16_t udp_sport, uint16_t tcp_sport)
{
	struct connection_store *current = config->store, *entry;

	/* Check if entry already exists */
	while (current != NULL) {
		/* TODO: if ADDR + TCP port match, but not UDP port, we have a
		 * conflict: check timestamp and either block the connection
		 * (e.g. different client behind the same IP), or replace (e.g.
		 * tunnel has been restarted) → we cannot predict that which
		 * one, seems safer to block
		 */
		if (current->ip_saddr.s_addr == saddr.s_addr &&
		    current->udp_sport == udp_sport &&
		    current->tcp_sport == tcp_sport) {
			/* TODO: Update timestamps here */
			return;
		}
		current = current->next;
	}

	/* Create new entry */
	entry = malloc(sizeof(struct connection_store));
	entry->ip_saddr = saddr;
	entry->udp_sport = udp_sport;
	entry->tcp_sport = tcp_sport;
	entry->next = config->store;
	config->store = entry;
	/* TODO: we need a way to remove old entries based on a timestamp
	 * because an entry will be create for each TCP connection, so very
	 * likely thousands per minute / second on a busy server.
	 */
}

/* Get stored UDP port for given IPv4 address and TCP port */
static uint16_t get_stored_port(struct tunnel_config *config,
				struct in_addr daddr, uint16_t tcp_dport)
{
	struct connection_store *current = config->store;

	while (current != NULL) {
		if (current->ip_saddr.s_addr == daddr.s_addr &&
		    current->tcp_sport == tcp_dport) {
			return current->udp_sport;
		}
		current = current->next;
	}

	return 0;
}

static int create_tun(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}

	return fd;
}

static int get_interface_ip(char *interface, struct in_addr *addr)
{
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	*addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	return 0;
}

static uint16_t ip_checksum(void *vdata, size_t length)
{
	/* Cast the data to 16 bit chunks */
	uint16_t *data = vdata;
	uint32_t sum = 0;

	while (length > 1) {
		sum += *data++;
		length -= 2;
	}

	/* Add left-over byte, if any */
	if (length > 0)
		sum += *(unsigned char *)data;

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

static uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int len)
{
	uint16_t checksum;
	int total_len;

	struct pseudo_header {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t tcp_length;
	};

	struct {
		struct pseudo_header hdr;
		unsigned char tcp[BUFFER_SIZE];
	} buffer;

	/* Fill pseudo header */
	buffer.hdr.source_address = ip->saddr;
	buffer.hdr.dest_address = ip->daddr;
	buffer.hdr.placeholder = 0;
	buffer.hdr.protocol = IPPROTO_TCP;
	buffer.hdr.tcp_length = htons(len);

	/* Allocate memory for the calculation */
	total_len = sizeof(struct pseudo_header) + len;

	/* Copy pseudo header and TCP header + data */
	memcpy(&buffer.tcp, tcp, len);

	/* Calculate checksum */
	checksum = ip_checksum(&buffer, total_len);

	return checksum;
}

static uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp,
			     void *payload, int payload_len)
{
	uint16_t checksum;
	char *pseudogram;
	int total_len;

	struct {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t udp_length;
	} pseudo_header;

	/* Fill pseudo header */
	pseudo_header.source_address = ip->saddr;
	pseudo_header.dest_address = ip->daddr;
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_UDP;
	pseudo_header.udp_length = udp->udp_len;

	/* Calculate total length and allocate memory */
	total_len = sizeof(pseudo_header) + ntohs(udp->udp_len);
	pseudogram = malloc(total_len);

	/* Copy headers and payload */
	memcpy(pseudogram, &pseudo_header, sizeof(pseudo_header));
	memcpy(pseudogram + sizeof(pseudo_header), udp, sizeof(struct udphdr));
	memcpy(pseudogram + sizeof(pseudo_header) + sizeof(struct udphdr),
	       payload, payload_len);

	/* Calculate checksum */
	checksum = ip_checksum(pseudogram, total_len);

	free(pseudogram);
	return checksum;
}

static void process_tun_packet(int tun_fd, int udp_fd,
			       struct tunnel_config *config)
{
	unsigned char buffer[BUFFER_SIZE], encap_buffer[BUFFER_SIZE];
	struct iphdr *ip = (struct iphdr *)buffer, *new_ip;
	struct sockaddr_in dest;
	struct in_addr daddr;
	struct tcphdr *tcp;
	struct udphdr *udp;
	uint16_t dport;
	int len;

	/* TODO: use len from ip->ihl and the size in byte should be >=
	 * IP_HEADER_LEN
	 * TODO: len should then be >= len(ip_hdr) + len(tcp_hdr),
	 * min 20 + 20
	 */
	tcp = (struct tcphdr *)(buffer + IP_HEADER_LEN);

	/* Create new IP + UDP header */
	new_ip = (struct iphdr *)encap_buffer;
	udp = (struct udphdr *)(encap_buffer + IP_HEADER_LEN);

	len = read(tun_fd, buffer, BUFFER_SIZE);
	if (len < 0) {
		perror("read");
		return;
	}

	/* Only process TCP packets */
	if (ip->protocol != IPPROTO_TCP) {
		return;
	}

	daddr.s_addr = ip->daddr;

	/* Determine destination UDP port based on endpoint_port or stored
	 * connection. This allows the local peer to communicate with multiple
	 * remote peers. Also, endpoint port cannot be hardcoded in case of port
	 * translation on peer's network; it must be found from previous
	 * connections.
	 */
	if (config->endpoint_port == 0) {
		dport = get_stored_port(config, daddr, ntohs(tcp->tcp_dest));
		if (dport == 0) {
			/* No stored port and no endpoint port configured */
			return;
		}
	} else {
		dport = config->endpoint_port;
	}

	/* Setup new IP header */
	memset(new_ip, 0, IP_HEADER_LEN);
	new_ip->version = 4;
	new_ip->ihl = 5;
	new_ip->tos = ip->tos;
	new_ip->tot_len = htons(len + UDP_HEADER_LEN);
	new_ip->id = htons(rand());
	new_ip->ttl = 64;
	new_ip->protocol = IPPROTO_UDP;
	new_ip->saddr = 0;
	new_ip->daddr = ip->daddr;

	/* Calculate IP header checksum */
	new_ip->check = 0;
	new_ip->check = ip_checksum(new_ip, IP_HEADER_LEN);

	/* Setup UDP header */
	udp->udp_source = 0;
	udp->udp_dest = htons(dport);
	udp->udp_len = htons(len - IP_HEADER_LEN + UDP_HEADER_LEN);

	/* Copy original TCP payload */
	memcpy(encap_buffer + IP_HEADER_LEN + UDP_HEADER_LEN,
	       buffer + IP_HEADER_LEN, len - IP_HEADER_LEN);

	/* Calculate UDP checksum */
	udp->udp_check = 0;
	udp->udp_check = udp_checksum(new_ip, udp, buffer + IP_HEADER_LEN,
				      len - IP_HEADER_LEN);

	/* Send encapsulated packet */
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = ip->daddr;
	dest.sin_port = htons(dport);

	sendto(udp_fd, encap_buffer, len + UDP_HEADER_LEN, 0,
	       (struct sockaddr *)&dest, sizeof(dest));
}

static void process_udp_packet(int tun_fd, int udp_fd,
			       struct tunnel_config *config)
{
	unsigned char buffer[BUFFER_SIZE], decap_buffer[BUFFER_SIZE];
	struct iphdr *ip = (struct iphdr *)buffer, *new_ip;
	struct in_addr src_addr_ip, tun_addr;
	struct tcphdr *tcp, *new_tcp;
	struct sockaddr_in src_addr;
	socklen_t src_addr_len;
	struct udphdr *udp;
	int len;

	src_addr_len = sizeof(src_addr);

	len = recvfrom(udp_fd, buffer, BUFFER_SIZE, 0,
		       (struct sockaddr *)&src_addr, &src_addr_len);
	if (len < 0) {
		perror("recvfrom");
		return;
	}

	udp = (struct udphdr *)(buffer + IP_HEADER_LEN);
	tcp = (struct tcphdr *)(buffer + IP_HEADER_LEN + UDP_HEADER_LEN);

	/* TODO: add some sanity checks, e.g. checking to see if the data in the
	 * buffer looks OK? e.g. checking if there are MPTCP options? Maybe
	 * something else?
	 */

	/* Store the connection information (peer's IPv4 addr, UDP port, TCP
	 * port) */
	if (config->endpoint_port == 0) {
		src_addr_ip.s_addr = src_addr.sin_addr.s_addr;
		store_connection(config, src_addr_ip, ntohs(src_addr.sin_port),
				 ntohs(tcp->tcp_source));
	}

	/* Get tunnel interface IP address */
	if (get_interface_ip(config->interface, &tun_addr) < 0) {
		fprintf(stderr, "Failed to get tunnel interface IP\n");
		return;
	}

	/* Create decapsulated packet */
	new_ip = (struct iphdr *)decap_buffer;

	/* Setup new IP header */
	memset(new_ip, 0, IP_HEADER_LEN);
	new_ip->version = 4;
	new_ip->ihl = 5;
	new_ip->tos = ip->tos;
	new_ip->tot_len = htons(len - UDP_HEADER_LEN);
	new_ip->id = htons(rand());
	new_ip->ttl = 64;
	new_ip->protocol = IPPROTO_TCP;
	new_ip->saddr = src_addr.sin_addr.s_addr;
	new_ip->daddr = tun_addr.s_addr;

	/* Calculate IP header checksum */
	new_ip->check = 0;
	new_ip->check = ip_checksum(new_ip, IP_HEADER_LEN);

	/* Copy TCP payload */
	memcpy(decap_buffer + IP_HEADER_LEN,
	       buffer + IP_HEADER_LEN + UDP_HEADER_LEN,
	       len - IP_HEADER_LEN - UDP_HEADER_LEN);

	/* Calculate TCP checksum
	 * TODO: it should not be needed on the server side if the TUN address
	 * is the same as the public one. (on the client side, we might not have
	 * the public IP)
	 */
	new_tcp = (struct tcphdr *)(decap_buffer + IP_HEADER_LEN);
	new_tcp->tcp_check = 0;
	new_tcp->tcp_check =
	    tcp_checksum(new_ip, new_tcp, len - IP_HEADER_LEN - UDP_HEADER_LEN);

	/* Write decapsulated packet to TUN interface */
	write(tun_fd, decap_buffer, len - UDP_HEADER_LEN);
}

int main(int argc, char *argv[])
{
	struct tunnel_config config = { };
	int maxfd, option, tun_fd, udp_fd;
	struct sockaddr_in addr;

	config.store = NULL;

	/* Parse command line arguments */
	static struct option long_options[] = {
		{ "interface", required_argument, 0, 'i' },
		{ "listen-port", required_argument, 0, 'l' },
		{ "bind-to-interface", required_argument, 0, 'b' },
		{ "endpoint-port", required_argument, 0, 'e' },
		{ 0, 0, 0, 0 }
	};

	while ((option = getopt_long(argc, argv, "i:l:b:e:", long_options,
				     NULL)) != -1) {
		switch (option) {
		case 'i':
			strncpy(config.interface, optarg, IFNAMSIZ - 1);
			break;
		case 'l':
			config.listen_port = atoi(optarg);
			break;
		case 'b':
			strncpy(config.bind_interface, optarg, IFNAMSIZ - 1);
			break;
		case 'e':
			config.endpoint_port = atoi(optarg);
			break;
		default:
			fprintf(stderr,
				"Usage: %s --interface tun0 --listen-port port --bind-to-interface dev --endpoint-port port\n",
				argv[0]);
			exit(1);
		}
	}

	/* Validate mandatory options */
	if (config.interface[0] == '\0' || config.listen_port == 0 ||
	    config.bind_interface[0] == '\0') {
		fprintf(stderr,
			"Error: interface, listen-port, and bind-to-interface are mandatory options\n");
		exit(1);
	}

	/* Create and configure TUN interface */
	tun_fd = create_tun(config.interface);
	if (tun_fd < 0) {
		fprintf(stderr, "Failed to create TUN interface\n");
		exit(1);
	}

	/* Create UDP socket */
	udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_fd < 0) {
		perror("socket");
		exit(1);
	}

	/* Bind UDP socket to specific interface */
	if (setsockopt
	    (udp_fd, SOL_SOCKET, SO_BINDTODEVICE, config.bind_interface,
	     strlen(config.bind_interface)) < 0) {
		perror("setsockopt");
		exit(1);
	}

	/* Bind UDP socket to listen port
	 * TODO: bind() is only needed when ListenPort is defined.
	 */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(config.listen_port);

	if (bind(udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(1);
	}

	printf("Tunnel started:\n");
	printf("TUN interface: %s\n", config.interface);
	printf("Bound to interface: %s\n", config.bind_interface);
	printf("Listening on port: %d\n", config.listen_port);
	if (config.endpoint_port) {
		printf("Endpoint port: %d\n", config.endpoint_port);
	}

	/* Main loop
	 * TODO: use multiple workers to be able to scale on a host with more
	 * than one core.
	 */
	fd_set readfds;
	while (1) {
		FD_ZERO(&readfds);
		FD_SET(tun_fd, &readfds);
		FD_SET(udp_fd, &readfds);
		maxfd = (tun_fd > udp_fd) ? tun_fd : udp_fd;

		/* TODO: use io_uring if possible? (or at least epoll) */
		if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
			perror("select");
			exit(1);
		}

		if (FD_ISSET(tun_fd, &readfds)) {
			process_tun_packet(tun_fd, udp_fd, &config);
		}

		if (FD_ISSET(udp_fd, &readfds)) {
			process_udp_packet(tun_fd, udp_fd, &config);
		}
	}

	return 0;
}
