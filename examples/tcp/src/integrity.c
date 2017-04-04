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

#define address 0xc0a8640a
#define BUF_SIZE 8
#define SERVER_PORT 10002

uint64_t total_rcv;
uint32_t err[6];
int64_t socket;
bool flag;
uint8_t buffer[BUF_SIZE +1];

bool bps_checker(void* context) {
	printf("%u bps, %u, %u, %u, %u, %u, %u, %u\n", total_rcv * 8, *debug_max, *debug_cur,  err[1], err[2], err[3], err[4], err[5]);
	err[2] = 0;
	err[3] = 0;
	err[5] = 0;
	
	total_rcv = 0;

	return true;
}

int32_t my_connected(uint64_t socket, uint32_t addr, uint16_t port, void* context) {
	printf("connected : %u, %u, %u\n", socket, addr, port);

	return 1;
}

int32_t my_received(uint64_t socket, void* buf, size_t len, void* context) {
	total_rcv += len;

	return 1;
}

int32_t my_sent(uint64_t socket, size_t len, void* context) {
	//printf("sent %s\n", buf);
	
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

	memset(buffer, 0xff, BUF_SIZE);
	
	event_init();
	total_rcv = 0;
	for(int i = 0; i < 6; i++) {
		err[i] = 0;
	}

	tcp_init();
	event_timer_add(bps_checker, NULL, 0, 1000000);
	
	uint32_t server_ip = 0xc0a86403;
	uint16_t server_port = SERVER_PORT;
	
	flag = false;
	socket = tcp_connect(nic, server_ip, server_port);
	printf("socket : %lu\n", socket);
	tcp_connected(socket, my_connected);
	tcp_sent(socket, my_sent);
	tcp_received(socket, my_received);	
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
	
	printf("test!!\n");
	NIC* nic = nic_get(0);
	
	uint64_t count = 0;
	
	printf("after nic_get()\n");
	while(1) {
		if(nic_has_input(nic)) {
			process(nic);
		}
		
		int ret;
		if((ret = tcp_send(socket, &count, BUF_SIZE)) < 0) {
			ret = -ret;
			err[ret]++;
		} else {
			count++;
		}

		
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

