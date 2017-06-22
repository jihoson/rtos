#ifndef __NET_TCP_H__
#define __NET_TCP_H__

#include <net/nic.h>

/**
 * @file
 * Transmission Control Protocol verion 4
 */

#define TCP_LEN			20		///< TCPv4 header length

uint32_t* debug_cur;
uint32_t* debug_max;
//uint32_t debug_same;
/**
 * TCPv4 header
 */
typedef struct _TCP {
	uint16_t	source;			///< Source port number (endian16)
	uint16_t	destination;		///< Destination port number (endian16)
	uint32_t	sequence;		///< Sequence number (endian32)
	uint32_t	acknowledgement;	///< Acknowledgement number (endian32)
	uint8_t		ns: 1;			///< ECN-nonce concealment protection flag
	uint8_t		reserved: 3;		///< Reserved
	uint8_t		offset: 4;		///< Data offset, TCP header length in 32-bit words
	uint8_t		fin: 1;			///< No more data from sender flag
	uint8_t		syn: 1;			///< Synchronize sequence number flag
	uint8_t		rst: 1;			///< Reset the connection flag
	uint8_t		psh: 1;			///< Push flag
	uint8_t		ack: 1;			///< Acknowledgement field is significant flag
	uint8_t		urg: 1;			///< Urgent pointer is significant flag
	uint8_t		ece: 1;			///< ECN-Echo flag
	uint8_t		cwr: 1;			///< Congestion Window Reduced flag
	uint16_t	window;			///< Window size (endian16)
	uint16_t	checksum;		///< Header and data checksum (endian16)
	uint16_t	urgent;			///< Urgent pointer (endian16)
	
	uint8_t		payload[0];		///< TCP payload
} __attribute__ ((packed)) TCP;

/**
 * TCPv4 pseudo header to calculate header checksum
 */
typedef struct _TCP_Pseudo {
	uint32_t        source;			///< Source address (endian32)
	uint32_t        destination;		///< Destination address (endian32)
	uint8_t         padding;		///< Zero padding
	uint8_t         protocol;		///< TCP protocol number, 0x06
	uint16_t        length;			///< Header and data length in bytes (endian32)
} __attribute__((packed)) TCP_Pseudo;

enum {
	SOL_SOCKET,
	IPPROTO_TCP
} _SOCK_LEVEL;

enum {
	SO_BROADCAST,
	SO_DEBUG,
	SO_DONTLINGER,
	SO_DONTROUTE,
	SO_OOBINLINE,
	SO_GROUP_PRIORITY,
	SO_KEEPALIVE,
	SO_LINGER,
	SO_RCVBUF,
	SO_REUSEADDR,
	SO_SNDBUF
} _SOL_SOCKET;

enum {
	TCP_NODELAY = 0x01
} _IPPROTO_TCP;

/**
 * Callbacks
 */
typedef int32_t (*TCP_CONNECTED)(uint64_t socket, uint32_t addr, uint16_t port, void* context);
/**
 * Once tcp_accepted callback is called. User has responsibility managing socket.
 * If user doesn't want to user socket, then should close socker using close().
 */
typedef int32_t (*TCP_ACCEPTED)(uint64_t new_socket, void* context);
typedef int32_t (*TCP_DISCONNECTED)(uint64_t socket, void* context);
typedef int32_t (*TCP_SENT)(uint64_t socket, size_t len, void* context);
typedef int32_t (*TCP_RECEIVED)(uint64_t socket, void* buf, size_t len, void* context);

// TODO: socket ID -> uint32_t
bool tcp_connected(uint64_t socket, TCP_CONNECTED connected);
bool tcp_accepted(uint64_t socket, TCP_ACCEPTED accepted);
bool tcp_disconnected(uint64_t socket, TCP_DISCONNECTED disconnected);
bool tcp_sent(uint64_t socket, TCP_SENT sent);
bool tcp_received(uint64_t socket, TCP_RECEIVED received);
bool tcp_context(uint64_t socket, void* context);
bool tcp_accepted(uint64_t socket, TCP_ACCEPTED accepted);

/**
  * Init valuse about tcp.
  *
  * @return false if initiation fail, else true.
  */
bool tcp_init();

/**
 * Process all TCP packet.
 *
 * @param packet Packet 
 * @return true if there is no error, else return false 
 */
bool tcp_process(Packet* packet);

/**
 * Get new tcp socket.
 *
 * @return 0 if error occured, else socket number.
 */
uint64_t tcp_new();

/**
 * Connect to remote computer, Send SYN packet.
 *
 * @param socket socket
 * @param nic NIC that IP is added
 * @param address remote computer's IP address(host endian)
 * @param port remote computer's port(host endian)
 * @return true if SYN msg were sent, else return false
 */
bool tcp_connect(uint64_t socket, NIC* nic, uint32_t address, uint16_t port);

/**
 * Send data.
 *
 * @param socket TCP socket 
 * @param data data's pointer
 * @param len data's length
 * @return -1 if fail to send, else sent data size
 */
// TODO: socket's size!! to uint32_t !!!!
int32_t tcp_send(uint64_t socket, void* data, const uint16_t len);

bool tcp_close(uint64_t socket);

bool tcp_bind(uint64_t socket, NIC* nic, uint32_t ip, uint16_t port);

bool tcp_listen(uint64_t socket, uint16_t backlog);

/**
 * set socket option.
 *
 * @param socket TCP socket
 * @param level network protocol layer level(SOL_SOCKET, IPPROTO_TCP)
 * @param optname option name
 * @param optval option value
 * @param optlen option value's length
 */
int setsockopt(uint64_t socket, int level, int optname, void* optval, int optlen);
#endif /* __NET_TCP_H__ */
