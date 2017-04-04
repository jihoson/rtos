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
#define BUF_SIZE 100
#define SERVER_PORT 10000
#define SOCK_NUM 1100
#define SERVER_IP	0xc0a86403

extern uint32_t count2;
uint64_t total_rcv;
uint32_t err[6];
uint64_t socket[SOCK_NUM];
uint32_t conn;
uint8_t buffer[BUF_SIZE +1];
NIC* nic;

bool bps_checker(void* context) {
//	printf("%u established, %u, %u, %u, %u, %u, %u, %u\n", total_rcv / BUF_SIZE, *debug_max, *debug_cur,  err[1], err[2], err[3], err[4], err[5]);
	printf("%u established, %u, %u, %u, %u, %u\n", total_rcv / BUF_SIZE,  err[1], err[2], err[3], err[4], err[5]);
	printf("conn : %u\n", conn);
	err[1] = 0;
	err[2] = 0;
	err[3] = 0;
	err[5] = 0;
	
	total_rcv = 0;

	return true;
}


int32_t my_connected(uint64_t socket, uint32_t addr, uint16_t port, void* context) {
	//printf("connected : %u, %u, %u\n", socket, addr, port);
	conn++;
	return 1;
}

int32_t my_received(uint64_t socket, void* buf, size_t len, void* context) {
	int ret;
	total_rcv += len;

	if((ret = tcp_send(socket, buf, len)) <= 0) {
		ret = -ret;
		err[ret]++;
	}
	return 1;
}

int32_t my_sent(uint64_t socket, size_t len, void* context) {
	//printf("sent %s\n", buf);
	
	return 1;
}

bool sender(void* context) {
	static int i = 0;
	static int alive_session = 0;
	int count;
	int ret;
	
	if((total_rcv / BUF_SIZE) != 1000) {
		printf("session unstable %d\n", total_rcv / BUF_SIZE);
		i = 0;
	} else {
		alive_session += 1000; 
		if(alive_session == SOCK_NUM) {
			printf("SOCK_NUM sessions ok!\n");
			alive_session = 0;
		}
	}

	total_rcv = 0;

	for(count = 0; count < 1000; count++) {
		if((ret = tcp_send(socket[i], buffer, BUF_SIZE)) <= 0) {
			ret = -ret;
			err[ret]++;
			//printf("send error\n");
		}

		i++;
		i = i % SOCK_NUM;
	}

	return true;
}

bool connecter(void* context) {
	static int i;
	int count;
	for(count = 0; count < 500; count++) {
		socket[i] = tcp_connect(nic, SERVER_IP, SERVER_PORT);
		if(socket[i] == 0) {
			printf("connect error!\n");
			while(1);
		}

		tcp_connected(socket[i], my_connected);
		tcp_sent(socket[i], my_sent);
		tcp_received(socket[i], my_received);

		i++;
	}

	if(i == SOCK_NUM) {
		printf("SOCK_NUM session connect ok!!\n");
		//event_timer_add(sender, NULL, 2000000, 1000000);
		return false;
	} else {
		return true;
	}
}

void destroy() {
}
void gdestroy() {
}

void ginit(int argc, char** argv) {
	nic = nic_get(0);
	if(nic != NULL) {
		nic_ip_add(nic, address);
	}

	memset(buffer, 0xff, BUF_SIZE);
	
	conn = 0;
	event_init();
	total_rcv = 0;
	for(int i = 0; i < 6; i++) {
		err[i] = 0;
	}
	tcp_init();
	event_timer_add(bps_checker, NULL, 0, 1000000);
	//event_timer_add(connecter, NULL, 2000000, 500000);
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
	
	int i = 0;
	int total_count = 0;

	NIC* nic = nic_get(0);
	while(1) {
		if(nic_has_input(nic)) {
			process(nic);
		}
		if(i == 10000 && total_count < SOCK_NUM) {
			uint64_t tmp_socket = tcp_connect(nic, SERVER_IP, SERVER_PORT);
			if(tmp_socket == 0) {
				printf("con error!\n");
				while(1);
			}

			tcp_connected(tmp_socket, my_connected);
			tcp_sent(tmp_socket, my_sent);
			tcp_received(tmp_socket, my_received);

			i = 0;
			total_count++;
		}

		i++;
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

