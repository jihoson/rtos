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
#define BUF_SIZE 4380
#define SERVER_PORT 10004

extern uint32_t count2;
uint64_t total_rcv;
uint64_t total_rcv2;
uint32_t err[6];
uint32_t err2[6];
int64_t socket;
int64_t socket2;
bool flag;
uint8_t buffer[BUF_SIZE +1];

bool bps_checker(void* context) {
	//printf("%u bps, %u, %u, %u, %u, %u, %u, %u\n", total_rcv * 8, *debug_max, *debug_cur,  err[1], err[2], err[3], err[4], err[5]);
	err[2] = 0;
	err[3] = 0;
	err[5] = 0;
	
	total_rcv = 0;
/*
	printf("%u bps, %u, %u, %u, %u, %u\n", total_rcv2 * 8, err2[1], err2[2], err2[3], err2[4], err2[5]);
	err2[2] = 0;
	err2[3] = 0;
	err2[5] = 0;
	
	total_rcv2 = 0;
*/
	return true;
}

int32_t my_connected(uint64_t socket, uint32_t addr, uint16_t port, void* context) {
	printf("connected : %u, %u, %u\n", socket, addr, port);

	//int val = 1;
	//setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));

	/*
	int ret = 0;
	if((ret = tcp_send(socket, buffer, BUF_SIZE)) < 0) {
		//ret = -ret;
		//err[ret]++;
		printf("error %d\n", ret);
	}
	*/
	int i = 0;
	
	for(i = 0; i < 50; i++) {
	tcp_send(socket, "AAAAAAAAAA", 10);
	tcp_send(socket, "BBBBBBBBBB", 10);
	tcp_send(socket, "CCCCCCCCCC", 10);
	}

	//printf("retval:%d\n", ret);

	printf("connected!!!!\n");
	return 1;
}

int32_t my_received(uint64_t socket, void* buf, size_t len, void* context) {
	total_rcv += len;

	return 1;
}

int32_t my_received2(uint64_t socket, void* buf, size_t len, void* context) {
	total_rcv2 += len;

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

	//memset(buffer, 0xAA, BUF_SIZE);
	memset(buffer, 0xAA, 1460);
	memset(buffer + 1460, 0xBB, 1460);
	memset(buffer + 1460 + 1460, 0xCC, 1460);
	
	event_init();
	total_rcv = 0;
	total_rcv2 = 0;
	for(int i = 0; i < 6; i++) {
		err[i] = 0;
	}
	for(int i = 0; i < 6; i++) {
		err2[i] = 0;
	}
	tcp_init();
	event_timer_add(bps_checker, NULL, 0, 1000000);
	
	uint32_t server_ip = 0xc0a864c8;
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

	while(1) {
		if(nic_has_input(nic)) {
			process(nic);
		}
		
		
		//int ret;
		/*
		if((ret = tcp_send(socket, buffer, BUF_SIZE)) < 0) {
			//ret = -ret;
			//err[ret]++;
			//printf("error %d\n", ret);
		}
		*/
		
		
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

