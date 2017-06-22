#include <stdio.h>
#include <thread.h>
#include <net/nic.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/ether.h>
#include <string.h>
#include <timer.h>
#include <util/event.h>
#include <util/list.h>
#include <unistd.h>
#include <readline.h>

#define address 0xc0a86404
#define BUF_SIZE 2460
#define SERVER_PORT 10000

extern uint32_t count2;
uint64_t total_rcv;
uint64_t socket;
bool flag;
uint8_t buffer[BUF_SIZE +1];

int32_t my_connected(uint64_t socket, uint32_t addr, uint16_t port, void* context) {

	printf("connected!!!!\n");
	return 1;
}

int32_t my_received(uint64_t socket, void* buf, size_t len, void* context) {
	tcp_send(socket, buffer, len);

	return 1;
}

int32_t my_sent(uint64_t socket, size_t len, void* context) {
	//printf("sent %s\n", buf);
	
	return 1;
}

int32_t my_accepted(uint64_t new_socket, void* context) {
	printf("new : %u\n", new_socket);

	return 1;
}

void destroy() {
}
void gdestroy() {
	tcp_close(socket);

	printf("tcp closed!!\n");
}

void ginit(int argc, char** argv) {
	NIC* nic = nic_get(0);
	if(nic != NULL) {
		nic_ip_add(nic, address);
	}

	memset(buffer, 0xAA, BUF_SIZE);
	
	event_init();
	tcp_init();
	//event_timer_add(bps_checker, NULL, 0, 1000000);
	
//	uint32_t server_ip = 0xc0a86403;
//	uint16_t server_port = SERVER_PORT;
	
	flag = false;
	socket = tcp_new();
	if(!socket) {
		printf("tcp_new() fail\n");
	}

	tcp_connected(socket, my_connected);
	tcp_sent(socket, my_sent);
	tcp_received(socket, my_received);	
	tcp_accepted(socket, my_accepted);

	tcp_bind(socket, nic, address, 10000);
	tcp_listen(socket, 10);
}
		
void init(int argc, char** argv) {

}

void process(NIC* nic){
	Packet* packet = nic_input(nic);
	if(!packet)
		return;

	Ether* ether = (Ether*)(packet->buffer + packet->start);

	if(endian16(ether->type) == ETHER_TYPE_ARP) {
		if(arp_process(packet))
			return;
	} else if(endian16(ether->type) == ETHER_TYPE_IPv4) {
		IP* ip = (IP*)ether->payload;

		if(ip->protocol == IP_PROTOCOL_ICMP && endian32(ip->destination) == address) {
		} else if(ip->protocol == IP_PROTOCOL_UDP) {
		
		} else if(ip->protocol == IP_PROTOCOL_TCP) {
			if(tcp_process(packet))
				return;
		}
	}
	
	if(packet)
		nic_free(packet);
}

int main(int argc, char** argv) {
	printf("Thread %d booting\n", thread_id());

	if(thread_id() == 0) {
		ginit(argc, argv);
	}
	
	thread_barrior();
	
	init(argc, argv);
	
	thread_barrior();
	
	NIC* nic = nic_get(0);

	while(1) {
		if(nic_has_input(nic)) {
			process(nic);
		}
		
		
	//	int ret;
		
		//if((ret = tcp_send(socket, buffer, BUF_SIZE)) < 0) {
	//	}
		
		
		event_loop();
	}

	thread_barrior();

	destroy();
	
	thread_barrior();
	
	if(thread_id() == 0) {
		gdestroy(argc, argv);
	}
	
	return 0;

}
