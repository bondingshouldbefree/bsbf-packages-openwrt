#include <fcntl.h>
#include <getopt.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Describe GLIBC-specific member names */
#ifdef __GLIBC__
#define uh_ulen		len
#define uh_sum		check
#define th_sum		check
#endif

/* TODO: Calculate the max needed buffer size to accommodate the memmove
 * operations.
 */
#define BUFFER_SIZE	2048
/* TODO: can be more if there are options, check IHL */
#define IP_HEADER_LEN	20
#define UDP_HEADER_LEN	8

/* struct connection_store -	This is the structure for holding peer's
 * 				connection information.
 * @peer_ip_addr:		The IPv4 address of the peer
 * @peer_udp_port:		The UDP port of the peer
 * @peer_tun_ip_addr:		The tunnel IPv4 address of the peer
 * @next:			Holding the pointer to the next entry
 */
struct connection_store {
	struct in_addr peer_ip_addr;
	uint16_t peer_udp_port;
	struct in_addr peer_tun_ip_addr;
	/* TODO: avoid using a list (O(n)), use a HashMap (O(1)) */
	struct connection_store *next;
	/* TODO: store a timestamp: to be able to remove old entries, and handle
	 * conflicts: same IP + TCP port, but different UDP port
	 */
};

/* struct tunnel_config -	This is the structure for holding the
 *				configuration of the programme.
 * @interface:			The name of the tunnel interface
 * @listen_port:		The UDP port to listen on
 * @bind_interface:		The interface to bind on
 * @endpoint_port:		The UDP port of the endpoint
 * @store:			Holding the pointer to the connection_store
 *				structure.
 */
struct tunnel_config {
	char interface[IFNAMSIZ];
	uint16_t listen_port;
	char bind_interface[IFNAMSIZ];
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

/* Store connection information: peer's IPv4 addr, UDP port, tunnel IPv4 addr */
static void store_connection(struct tunnel_config *config, struct in_addr saddr,
			     uint16_t udp_sport, struct in_addr tun_saddr)
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
		if (current->peer_ip_addr.s_addr == saddr.s_addr &&
		    current->peer_udp_port == udp_sport &&
		    current->peer_tun_ip_addr.s_addr == tun_saddr.s_addr) {
			/* TODO: Update timestamps here */
			return;
		}
		current = current->next;
	}

	/* Create new entry */
	entry = malloc(sizeof(struct connection_store));
	entry->peer_ip_addr = saddr;
	entry->peer_udp_port = udp_sport;
	entry->peer_tun_ip_addr = tun_saddr;
	entry->next = config->store;
	config->store = entry;
	/* TODO: we need a way to remove old entries based on a timestamp
	 * because an entry will be create for each TCP connection, so very
	 * likely thousands per minute / second on a busy server.
	 */
}

/* Get stored IPv4 addr for given tunnel IPv4 address */
static struct in_addr get_stored_addr(struct tunnel_config *config,
				      struct in_addr tun_addr)
{
	struct in_addr empty_addr = {.s_addr = INADDR_ANY };
	struct connection_store *current = config->store;

	while (current != NULL) {
		if (current->peer_tun_ip_addr.s_addr == tun_addr.s_addr) {
			return current->peer_ip_addr;
		}
		current = current->next;
	}

	/* TODO: This will never return. If dport is found, above is going to return. */
	return empty_addr;
}

/* Get stored UDP port for given tunnel IPv4 address */
static uint16_t get_stored_port(struct tunnel_config *config,
				struct in_addr tun_addr)
{
	struct connection_store *current = config->store;

	while (current != NULL) {
		if (current->peer_tun_ip_addr.s_addr == tun_addr.s_addr) {
			return current->peer_udp_port;
		}
		current = current->next;
	}

	return 0;
}

static int create_tun(char *dev)
{
	struct ifreq ifr = { };
	int err, fd;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		return fd;
	}

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
	struct ifreq ifr = { };
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

	/* Copy pseudo header, TCP header, and payload */
	memcpy(&buffer.tcp[0], tcp, len);

	/* Calculate checksum */
	checksum = ip_checksum(&buffer, total_len);

	return checksum;
}

static uint16_t udp_checksum(struct iphdr *ip, struct udphdr *udp,
			     void *payload, int payload_len)
{
	uint16_t checksum;
	int total_len;

	struct pseudo_header {
		uint32_t source_address;
		uint32_t dest_address;
		uint8_t placeholder;
		uint8_t protocol;
		uint16_t udp_length;
	};

	struct {
		struct pseudo_header hdr;
		unsigned char udp[BUFFER_SIZE];
	} buffer;

	/* Fill pseudo header */
	buffer.hdr.source_address = ip->saddr;
	buffer.hdr.dest_address = ip->daddr;
	buffer.hdr.placeholder = 0;
	buffer.hdr.protocol = IPPROTO_UDP;
	buffer.hdr.udp_length = udp->uh_ulen;

	/* Calculate total length and allocate memory */
	total_len = sizeof(struct pseudo_header) + ntohs(udp->uh_ulen);

	/* Copy headers and payload */
	memcpy(&buffer.udp[0], udp, sizeof(struct udphdr));
	memcpy(&buffer.udp[sizeof(struct udphdr)], payload, payload_len);

	/* Calculate checksum */
	checksum = ip_checksum(&buffer, total_len);

	return checksum;
}

static void process_tun_packet(int tun_fd, int udp_fd,
			       struct tunnel_config *config)
{
	unsigned char buffer[BUFFER_SIZE];
	struct sockaddr_in dest = { };
	struct in_addr daddr;
	struct iphdr *ip;
	uint16_t dport;
	int len;

	len = read(tun_fd, buffer, BUFFER_SIZE);
	if (len < 0) {
		perror("read");
		return;
	}

	ip = (struct iphdr *)buffer;

	/* Determine destination UDP port and IPv4 address based on
	 * endpoint_port or stored connection. This allows the local peer to
	 * communicate with multiple remote peers. Also, endpoint port cannot be
	 * hardcoded in case of port translation on peer's network; it must be
	 * found from previous connections.
	 */
	if (config->endpoint_port == 0) {
		struct in_addr peer_tun_ip_addr = {.s_addr = ip->daddr };

		dport = get_stored_port(config, peer_tun_ip_addr);
		if (dport == 0) {
			return;
		}

		daddr = get_stored_addr(config, peer_tun_ip_addr);
		/* TODO: The check below is unnecessary. If dport is found, this
		 * will be there as well.
		 */
		if (daddr.s_addr == INADDR_ANY) {
			return;
		}
	} else {
		dport = config->endpoint_port;
		daddr.s_addr = ip->daddr;
	}

	/* Send encapsulated packet */
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = daddr.s_addr;
	dest.sin_port = htons(dport);

	sendto(udp_fd, buffer, len, 0, (struct sockaddr *)&dest, sizeof(dest));
}

static void process_udp_packet(int tun_fd, int udp_fd,
			       struct tunnel_config *config)
{
	struct sockaddr_in sock_src = { };
	unsigned char buffer[BUFFER_SIZE];
	struct in_addr tun_ip_addr;
	socklen_t sock_len;
	struct iphdr *ip;
	int len;

	sock_len = sizeof(sock_src);

	len = recvfrom(udp_fd, buffer, BUFFER_SIZE, 0,
		       (struct sockaddr *)&sock_src, &sock_len);
	if (len < 0) {
		perror("recvfrom");
		return;
	}

	ip = (struct iphdr *)(buffer);

	/* TODO: add some sanity checks, e.g. checking to see if the data in the
	 * buffer looks OK? e.g. checking if there are MPTCP options? Maybe
	 * something else?
	 */

	/* Store the connection information: Peer's IPv4 addr, UDP port, tunnel
	 * IPv4 addr.
	 */
	if (config->endpoint_port == 0) {
		struct in_addr peer_ip_addr, peer_tun_ip_addr;

		peer_ip_addr.s_addr = sock_src.sin_addr.s_addr;
		peer_tun_ip_addr.s_addr = ip->saddr;

		store_connection(config, peer_ip_addr, ntohs(sock_src.sin_port),
				 peer_tun_ip_addr);
	} else {
		ip->saddr = sock_src.sin_addr.s_addr;
	}

	/* Get tunnel interface IP address */
	if (get_interface_ip(config->interface, &tun_ip_addr) < 0) {
		fprintf(stderr, "Failed to get tunnel interface IP\n");
		return;
	}

	ip->daddr = tun_ip_addr.s_addr;

	/* Recalculate IP header checksum after modifying addresses */
	ip->check = 0;
	ip->check = ip_checksum(ip, IP_HEADER_LEN);

	/* Recalculate TCP or UDP checksums if present */
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *)(buffer + IP_HEADER_LEN);

		tcp->th_sum = 0;
		tcp->th_sum = tcp_checksum(ip, tcp, len - IP_HEADER_LEN);
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)(buffer + IP_HEADER_LEN);

		udp->uh_sum = 0;
		udp->uh_sum = udp_checksum(ip, udp,
					   buffer + IP_HEADER_LEN +
					   UDP_HEADER_LEN,
					   len - IP_HEADER_LEN -
					   UDP_HEADER_LEN);
	}

	/* Write decapsulated packet to TUN interface */
	write(tun_fd, buffer, len);
}

int main(int argc, char *argv[])
{
	int maxfd, option, tun_fd, udp_fd;
	struct tunnel_config config = { };
	struct sockaddr_in addr = { };

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
	 * TODO: bind() is only needed when ListenPort is defined. ListenPort
	 * option can be made non-mandatory. Either EndpointPort or ListenPort
	 * must be described.
	 */
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
