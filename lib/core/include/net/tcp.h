#ifndef __NET_TCP_H__
#define __NET_TCP_H__

#include <net/nic.h>

/**
 * @file
 * Transmission Control Protocol verion 4
 */

#define TCP_LEN			20		///< TCPv4 header length

int32_t* debug_cur;
int32_t* debug_max;
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

/**
 * Callbacks
 */
typedef int32_t (*TCP_CONNECTED)(uint64_t socket, uint32_t addr, uint16_t port, void* context);
typedef int32_t (*TCP_BOUND)(uint64_t socket, uint32_t addr, uint16_t port, void* context);
typedef int32_t (*TCP_DISCONNECTED)(uint64_t socket, void* context);
typedef int32_t (*TCP_SENT)(uint64_t socket, size_t len, void* context);
typedef int32_t (*TCP_RECEIVED)(uint64_t socket, void* buf, size_t len, void* context);

// TODO: socket ID -> uint32_t
bool tcp_connected(uint64_t socket, TCP_CONNECTED connected);
bool tcp_bound(uint64_t socket, TCP_BOUND bound);
bool tcp_disconnected(uint64_t socket, TCP_DISCONNECTED disconnected);
bool tcp_sent(uint64_t socket, TCP_SENT sent);
bool tcp_received(uint64_t socket, TCP_RECEIVED received);
bool tcp_context(uint64_t socket, void* context);

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
 * Connect to remote computer, Send SYN packet.
 *
 * @param nic NIC that IP is added
 * @param address remote computer's IP address
 * @param port remote computer's port
 * @return 0 if error occurred, else socket number used as a tcb_key internally
 */
// TODO: uint32_t return, 0 -> 0
// ERROR; return 0, errno
// TODO: socket's size!!
uint64_t tcp_connect(NIC* nic, uint32_t address, uint16_t port);

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

#endif /* __NET_TCP_H__ */
