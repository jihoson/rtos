#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <gmalloc.h>
#include <timer.h>
#include <net/nic.h>
#include <net/packet.h>
#include <net/ether.h>
#include <net/arp.h>
#include <net/interface.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/checksum.h>
#include <util/event.h>
#include <util/list.h>
#include <util/map.h>

#define MAX_SEQNUM	2147483648

#define FIN	0x01
#define SYN	0x02
#define RST	0x04
#define PSH	0x08
#define ACK	0x10
#define URG	0x20
#define ECE	0x40
#define CWR	0x80

#define RECV_WND_MAX	8388480//4000
#define ACK_TIMEOUT	2000	// 2 sec
#define MSL		10000000	// 10 sec 
#define RECV_WND_SCALE	128	
#define SMSS	1460	//Sender Maximum Segment Size

extern void* __gmalloc_pool;

typedef enum {
	TCP_CLOSED,
	TCP_LISTEN,
	TCP_SYN_RCVD,
	TCP_SYN_SENT,
	TCP_ESTABLISHED,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_FIN_WAIT_1,
	TCP_FIN_WAIT_2,
	TCP_CLOSING,
	TCP_TIME_WAIT,
	TCP_TCB_CREATED,
	TCP_STATE_COUNT
} TCP_STATE;


typedef struct {
	uint32_t sequence;
	uint32_t len;
	uint64_t timeout;
	Packet* packet;
} Segment;

typedef struct {
	uint32_t sip;
	uint16_t sport;
	
	uint64_t dmac;
	uint32_t dip;
	uint32_t dport;

	uint32_t sequence;
	uint32_t acknowledgement;
	uint64_t timer_id;
	uint64_t timeout;

	int32_t state;

	//callback
	void* context;
	TCP_CONNECTED connected;
	TCP_DISCONNECTED disconnected;
	TCP_SENT sent;
	TCP_RECEIVED received;
	TCP_BOUND bound;

	List* unack_list;	// sent segment but no ack.
	Map* rcv_buffer;
	uint32_t snd_wnd_max;
	uint32_t snd_wnd_cur;
	uint16_t snd_mss;
	uint8_t snd_wnd_scale;

	uint32_t recv_wnd_max;
	uint32_t last_ack;
	uint16_t recv_mss;
	uint8_t recv_wnd_scale;
	NIC* nic;

	bool delayed_ack_flag;
	uint8_t syn_counter;
	uint64_t delayed_ack_timeout;
	uint32_t cwnd;
	uint32_t ssthresh;
} TCB;

typedef bool (*tcp_proc_func)(TCB* tcb, Packet* packet);

static bool process_closed(TCB* tcb, Packet* in_packet);
static bool process_listen(TCB* tcb, Packet* in_packet);
static bool process_syn_rcvd(TCB* tcb, Packet* in_packet);
static bool process_syn_sent(TCB* tcb, Packet* in_packet);
static bool process_established(TCB* tcb, Packet* in_packet);
static bool process_close_wait(TCB* tcb, Packet* in_packet);
static bool process_last_ack(TCB* tcb, Packet* in_packet);
static bool process_fin_wait_1(TCB* tcb, Packet* in_packet);
static bool process_fin_wait_2(TCB* tcb, Packet* in_packet);
static bool process_closing(TCB* tcb, Packet* in_packet);
static bool process_time_wait(TCB* tcb, Packet* in_packet);

tcp_proc_func proc_func[TCP_STATE_COUNT] = {
	[TCP_CLOSED] = process_closed,
	[TCP_LISTEN] = process_listen,
	[TCP_SYN_RCVD] = process_syn_rcvd,
	[TCP_SYN_SENT] = process_syn_sent,
	[TCP_ESTABLISHED] = process_established,
	[TCP_CLOSE_WAIT] = process_close_wait,
	[TCP_LAST_ACK] = process_last_ack,
	[TCP_FIN_WAIT_1] = process_fin_wait_1,
	[TCP_FIN_WAIT_2] = process_fin_wait_2,
	[TCP_CLOSING] = process_closing,
	[TCP_TIME_WAIT] = process_time_wait,
};

static uint32_t ip_id;
static Map* tcbs;
static List* time_wait_list;
static List* conn_try_list;

static Packet* packet_create(TCB* tcb, uint8_t flags, const void* data, int len);
static bool packet_out(TCB* tcb, Packet* packet, uint16_t len); 
static bool unacked_segment_timer(void* context); 
static bool delayed_ack_timer(void* context); 
static bool tcp_try_connect(void* context); 
static bool time_wait_timer(void* context);

static bool tcp_port_alloc0(NIC* nic, uint32_t addr, uint16_t port) {
	IPv4Interface* interface = nic_ip_get(nic, addr);
	if(!interface->tcp_ports) {
		interface->tcp_ports = set_create(64, set_uint64_hash, set_uint64_equals, nic->pool);
		if(!interface->tcp_ports)
			return false;
	}

	if(set_contains(interface->tcp_ports, (void*)(uintptr_t)port))
		return false;

	return set_put(interface->tcp_ports, (void*)(uintptr_t)port);
}

static uint16_t tcp_port_alloc(NIC* nic, uint32_t addr) {
	IPv4Interface* interface = nic_ip_get(nic, addr);
	if(!interface->tcp_ports) {
		interface->tcp_ports = set_create(64, set_uint64_hash, set_uint64_equals, nic->pool);
		if(!interface->tcp_ports)
			return 0;
	}

	uint16_t port = interface->tcp_next_port;
	if(port < 49152)
		port = 49152;
	
	while(set_contains(interface->tcp_ports, (void*)(uintptr_t)port)) {
		if(++port < 49152)
			port = 49152;
	}	

	if(!set_put(interface->tcp_ports, (void*)(uintptr_t)port))
		return 0;
	
	interface->tcp_next_port = port;
	
	return port;
}

static void tcp_port_free(NIC* nic, uint32_t addr, uint16_t port) {
	IPv4Interface* interface = nic_ip_get(nic, addr);
	if(interface == NULL)
		return;
	
	set_remove(interface->tcp_ports, (void*)(uintptr_t)port);
}

static void tcp_pack(Packet* packet, uint16_t tcp_body_len) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;
	
	uint16_t tcp_len = TCP_LEN + tcp_body_len;
	
	TCP_Pseudo pseudo;
	pseudo.source = ip->source;
	pseudo.destination = ip->destination;
	pseudo.padding = 0;
	pseudo.protocol = ip->protocol;
	pseudo.length = endian16(tcp_len);
	
	tcp->checksum = 0;
	uint32_t sum = (uint16_t)~checksum(&pseudo, sizeof(pseudo)) + (uint16_t)~checksum(tcp, tcp_len);
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	tcp->checksum = endian16(~sum);
	
	ip_pack(packet, tcp_len);
}

static uint32_t tcp_init_seqnum() {
	//random(); find random function
	uint64_t time;
	uint32_t* p = (uint32_t*)&time;
	asm volatile("rdtsc" : "=a"(p[0]), "=d"(p[1]));
	return time % MAX_SEQNUM;
}

static void ip_init_id() {
	//TODO: maybe need something different
	ip_id = 0x8000;
}

static uint32_t ip_get_id(int ack) {
	if(ack == 1) {
		return ip_id;
	} else {
		ip_id++;
	}
	return	ip_id;
}

static TCB* tcb_get(uint64_t tcb_key) {
	TCB* tcb = map_get(tcbs, (void*)(uintptr_t)tcb_key);

	if(tcb == NULL) {
		//printf("tcb is null \n");
		return NULL;
	}
	return tcb;
}

// hash functions using Jenkins's one-at-a-time hash
static uint64_t map_jenkins_hash(void* arg_key) {
	uint8_t* key = (uint8_t*)&arg_key;
	uint32_t hash;
	uint8_t i, len = 6;

	for(hash = i = 0; i < len; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return (uint64_t)hash;
}

bool tcp_init() {
	tcbs = map_create(20, map_jenkins_hash, map_uint64_equals, __gmalloc_pool);
	if(!tcbs) {
		printf("tcbs create fail\n");

		return false;
	}
	
	time_wait_list = list_create(__gmalloc_pool);
	if(!time_wait_list) {
		printf("time_wait_list create fail\n");
		
		map_destroy(tcbs);

		return false;
	}

	conn_try_list = list_create(__gmalloc_pool);
	if(!conn_try_list) {
		printf("conn_try_list create fail\n");
		
		list_destroy(time_wait_list);
		map_destroy(tcbs);

		return false;
	}
	
	event_timer_add(unacked_segment_timer, NULL, 0, 200000);
	event_timer_add(delayed_ack_timer, NULL, 0, 100000);

	ip_init_id();	// TODO: think about layer. init ip_id in tcp stack...

	return true;
}

/*
 * tcb_key_create
 * @params network endian.
 */
static uint64_t tcb_key_create(uint32_t sip, uint16_t sport) {
	uint64_t tcb_key = 0;
	tcb_key = ((uint64_t)sip << 16) + sport;

	return tcb_key;
}

static uint8_t wnd_scale_get(uint32_t recv_wnd_max) {
	uint8_t scale = 0;

	while(recv_wnd_max > 0xffff) {
		recv_wnd_max >>= 1;
		scale++;
	}

	return scale;
}

static TCB* tcb_create(NIC* nic, uint32_t sip, uint32_t dip, uint16_t dport) {
	TCB* tcb = (TCB*)gmalloc(sizeof(TCB));
	if(tcb == NULL) {
		printf("tcb NULL\n");
		return NULL;
	}
	
	tcb->unack_list = list_create(__gmalloc_pool);
	if(tcb->unack_list == NULL) {
		printf("list_create error\n");
		gfree(tcb);
		return NULL;
	}

	tcb->rcv_buffer = map_create(50, map_uint64_hash, map_uint64_equals, __gmalloc_pool);
	if(!tcbs) {
		printf("tcbs create fail\n");
		gfree(tcb);
		return NULL;
	}

	tcb->sip = sip; 
	tcb->sport = tcp_port_alloc(nic, sip);

	//printf("port : %u\n", tcb->sport);
	if(tcb->sport == 0) {
		printf("sport alloc fail\n");
		gfree(tcb);
		return NULL;
	}

	tcb->dip = dip;
	tcb->dport = dport;
	
	tcb->state = TCP_CLOSED;
	tcb->sequence = tcp_init_seqnum();
	tcb->acknowledgement = 0;
	
	tcb->recv_wnd_max = RECV_WND_MAX;
	tcb->recv_wnd_scale = wnd_scale_get(tcb->recv_wnd_max);
		
	tcb->snd_wnd_max = 0;
	tcb->snd_wnd_cur = 0;
	tcb->snd_wnd_scale = 1;

	tcb->context = NULL;
	tcb->connected = NULL;
	tcb->disconnected = NULL;
	tcb->sent = NULL;
	tcb->received = NULL;
	tcb->bound = NULL;

	tcb->delayed_ack_flag = false;
	tcb->delayed_ack_timeout = 0;
	tcb->syn_counter = 0;

	tcb->nic = nic;
	// debug
	debug_max = &(tcb->snd_wnd_max);
	debug_cur = &(tcb->snd_wnd_cur);

	return tcb;
}

static bool tcb_destroy(TCB* tcb) {
	tcp_port_free(tcb->nic, tcb->sip, tcb->sport);
	
	ListIterator iter;
	list_iterator_init(&iter, tcb->unack_list);

	while(list_iterator_has_next(&iter)) {
		Segment* seg = list_iterator_next(&iter);
		nic_free(seg->packet);
		list_iterator_remove(&iter);
		gfree(seg);
	}

	list_destroy(tcb->unack_list);
	
	uint64_t tcb_key = tcb_key_create(endian32(tcb->sip), endian16(tcb->sport));
	void* result = map_remove(tcbs, (void*)tcb_key);
	if(!result)
		printf("map_remove error\n");
	
	gfree(tcb);
	printf("tcb_destory!!\n");
	
	return true;
}

// TODO: maybe need routing func that finds src_ip from ni.
static uint32_t route(NIC* nic, uint32_t dst_addr, uint16_t des_port) {
	IPv4Interface* interface = NULL;
	uint32_t ip = 0;

	Map* interfaces = nic_config_get(nic, NIC_ADDR_IPv4);
	if(!interfaces)
		return 0;

	MapIterator iter;
	map_iterator_init(&iter, interfaces);
	while(map_iterator_has_next(&iter)) {
		MapEntry* entry = map_iterator_next(&iter);
		interface = entry->data;
		ip = (uint32_t)(uint64_t)entry->key;
		break;
	}
	
	if(!interface)
		return 0;

	return ip;
}

uint64_t tcp_connect(NIC* nic, uint32_t dst_addr, uint16_t dst_port) {
	uint32_t src_addr = route(nic, dst_addr, dst_port);

	TCB* tcb = tcb_create(nic, src_addr, dst_addr, dst_port);
	if(tcb == NULL) {
		printf("tcb NULL\n");
		return 0;
	}

	uint64_t tcb_key = tcb_key_create(endian32(tcb->sip), endian16(tcb->sport));	
	//printf("key : %u\n", tcb_key);

	if(!map_put(tcbs, (void*)tcb_key, (void*)(uintptr_t) tcb)) {
		printf("map_put error\n");
		tcb_destroy(tcb);
		return 0;
	}

	uint64_t mac = arp_get_mac(nic, tcb->dip, tcb->sip);

	if(mac == 0xffffffffffff) {
		event_timer_add(tcp_try_connect, tcb, 0, 100000);
	} else {
		if(tcp_try_connect(tcb)) {
			tcb_destroy(tcb);
			
			return 0;
		}
	}  

	return tcb_key;
}

bool tcp_close(uint64_t socket) {
	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return false;

	Packet* packet = packet_create(tcb, FIN | ACK, NULL, 0);
	if(packet)
		return false;

	if(!packet_out(tcb, packet, 0))
		return false;
	
	tcb->state = TCP_FIN_WAIT_1;
	tcb->snd_wnd_max = 0;
	tcb->sequence += 1;

	return true;
}

int32_t tcp_send(uint64_t socket, void* data, const uint16_t len) {
	if(len == 0)
		return 0;

	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return -1;

	if(tcb->state != TCP_ESTABLISHED) {
		//return -1;	
		return -2;
	}
	
	if(tcb->snd_wnd_max < tcb->cwnd) {
		if(tcb->snd_wnd_max - tcb->snd_wnd_cur < len) {
			//printf("port:%u, swm:%u, swc:%u, cwnd:%u\n", tcb->sport, tcb->snd_wnd_max, tcb->snd_wnd_cur, tcb->cwnd);
			//return -2;
			return -3;
		}
	} else {
		if(tcb->cwnd - tcb->snd_wnd_cur < len)
	//		return -2;
			return 0;
	}

	if(!nic_output_available(tcb->nic))
		return -3;
	
	// debug
	/*
	if(tcb->snd_wnd_max < tcb->cwnd) {
		memcpy(data, &(tcb->snd_wnd_max), 4);
		memcpy((int32_t*)data + 1, &(tcb->snd_wnd_cur), 4);
	} else {
		memcpy(data, &(tcb->cwnd), 4);
		memcpy((int32_t*)data + 1, &(tcb->cwnd), 4);
	}
	*/

	Packet* packet = packet_create(tcb, ACK | PSH, data, len);
	if(!packet)
		return -4;

	if(!packet_out(tcb, packet, len))
		return -5;
	
	tcb->snd_wnd_cur += len;
	tcb->sequence += len;
	tcb->delayed_ack_flag = false;

	return len;	
}

bool tcp_process(Packet* packet) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
	if(endian16(ether->type) != ETHER_TYPE_IPv4)
		return false;

	IP* ip = (IP*)ether->payload;

	if(!nic_ip_get(packet->nic, endian32(ip->destination)))
		return false;
	
	if(ip->protocol != IP_PROTOCOL_TCP)
		return false;
	
	TCP* tcp = (TCP*)ip->body;

	uint64_t tcb_key = tcb_key_create(ip->destination,tcp->destination);

	TCB* tcb = tcb_get(tcb_key);
	if(!tcb)
		return false;

	if(endian16(tcp->source) != tcb->dport) {
		return false;
	}

	if(!proc_func[tcb->state](tcb, packet))
		return false;
	
	nic_free(packet);
	return true;
}

static Packet* packet_create(TCB* tcb, uint8_t flags, const void* data, int len) {
	NIC* nic = tcb->nic;

	Packet* packet;

	if(flags & SYN)
		packet = nic_alloc(nic, sizeof(Ether) + sizeof(IP) + sizeof(TCP) + 4 + 4/* option */ + len);
	else
		packet = nic_alloc(nic, sizeof(Ether) + sizeof(IP) + sizeof(TCP) + len);

	if(!packet)
		return NULL;

	Ether* ether = (Ether*)(packet->buffer + packet->start);
	ether->dmac = endian48(tcb->dmac);
	ether->smac = endian48(nic->mac);
	ether->type = endian16(ETHER_TYPE_IPv4);
	
	IP* ip = (IP*)ether->payload;
	ip->ihl = endian8(5);
	ip->version = endian8(4);
	ip->ecn = endian8(0); 
	ip->dscp = endian8(0);

	ip_id = ip_get_id((flags & ACK) >> 4);
	ip->id = endian16(ip_id);
	ip->flags_offset = 0x40;
	ip->ttl = endian8(IPDEFTTL);
	ip->protocol = endian8(IP_PROTOCOL_TCP);
	ip->source = endian32(tcb->sip);
	ip->destination = endian32(tcb->dip);
	
	TCP* tcp = (TCP*)ip->body;
	tcp->source = endian16(tcb->sport);
	tcp->destination = endian16(tcb->dport);
	tcp->sequence = endian32(tcb->sequence);
	tcp->acknowledgement = endian32(tcb->acknowledgement);
	tcp->ns = endian8(0);
	tcp->reserved = endian8(0);
	tcp->fin = flags & FIN; 
	tcp->syn = (flags & SYN) >> 1;
	tcp->rst = (flags & SYN) >> 2;
	tcp->psh = (flags & PSH) >> 3;
	tcp->ack = (flags & ACK) >> 4;
	tcp->urg = (flags & URG) >> 5;
	tcp->ece = (flags & ECE) >> 6;
	tcp->cwr = (flags & CWR) >> 7;
	tcp->window = endian16(tcb->recv_wnd_max);
	tcp->urgent = endian16(0);
	
	if(tcp->syn) {
		tcp->offset = endian8(7);
		//uint32_t mss_option = endian32(0x020405b4);
		uint32_t mss_option = endian32(0x02040578);
		uint32_t win_option = endian32(0x01030300 + tcb->recv_wnd_scale);

		memcpy(tcp->payload, &mss_option, 4);
		memcpy((uint8_t*)(tcp->payload) + 4, &win_option, 4);

		tcp_pack(packet, len + 4 + 4);
	} else {
		tcp->offset = endian8(5);
		memcpy((uint8_t*)tcp + tcp->offset * 4, data, len);

		tcp_pack(packet, len);
	}
	
	return packet;
}

static bool packet_out(TCB* tcb, Packet* packet, uint16_t len) {
	if(!packet)
		return false;

	NIC* nic = packet->nic;
	
	if(len == 0)
		return nic_output(nic, packet);

	if(nic_output_dup(nic, packet)) {
		Segment* segment = gmalloc(sizeof(Segment));
		if(!segment) {
			printf("seg malloc fail\n");	// could be wrong
			return false;
		}

		segment->timeout = timer_ms() + ACK_TIMEOUT;
		segment->len = len;
		segment->sequence = tcb->sequence;
		segment->packet = packet;

		if(!list_add(tcb->unack_list, segment)) {
			printf("list add fail\n");	//could be wrong
			
			gfree(segment);
			nic_free(packet);
			return false;
		}

		return true;
	} else {
		nic_free(packet);

		return false;
	}
}

bool tcp_connected(uint64_t socket, TCP_CONNECTED connected) {
	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return false;

	tcb->connected = connected;

	return true;
}

bool tcp_bound(uint64_t socket, TCP_BOUND bound) {
	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return false;

	tcb->bound = bound;

	return true;
}

bool tcp_disconnected(uint64_t socket, TCP_DISCONNECTED disconnected) {
	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return false;

	tcb->disconnected = disconnected;

	return true;
}

bool tcp_sent(uint64_t socket, TCP_SENT sent) {
	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return false;

	tcb->sent = sent;

	return true;
}

bool tcp_received(uint64_t socket, TCP_RECEIVED received) {
	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return false;

	tcb->received = received;

	return true;
}

bool tcp_context(uint64_t socket, void* context) {
	TCB* tcb = tcb_get(socket);
	if(!tcb)
		return false;

	tcb->context = context;

	return true;
}

static bool unacked_segment_timer(void* context) {
	uint64_t current = timer_ms();

	if(!tcbs) 
		return true;

	MapIterator map_iter;
	map_iterator_init(&map_iter, tcbs);

	while(map_iterator_has_next(&map_iter)) {
		MapEntry* entry = map_iterator_next(&map_iter);
		TCB* tcb = entry->data;

		if(!tcb->unack_list)
			continue;

		ListIterator seg_iter;
		list_iterator_init(&seg_iter, tcb->unack_list);

		while(list_iterator_has_next(&seg_iter)) {
			Segment* segment = (Segment*)list_iterator_next(&seg_iter);

			if(segment->timeout > current) 
				break;

			// retransmission
			if(packet_out(tcb, segment->packet, segment->len)) {
				if(tcb->snd_wnd_cur / 2 > 2 * SMSS)
					tcb->ssthresh = tcb->snd_wnd_cur / 2;
				else
					tcb->ssthresh = 2 * SMSS;

				tcb->cwnd = SMSS;

				gfree(segment);

				list_iterator_remove(&seg_iter);

				//printf("retrans!\n");
			}
		}
	}

	return true;
}

static bool delayed_ack_timer(void* context) {
	uint64_t current = timer_ms();

	if(!tcbs)
		return true;

	MapIterator map_iter;
	map_iterator_init(&map_iter, tcbs);

	while(map_iterator_has_next(&map_iter)) {
		MapEntry* entry = map_iterator_next(&map_iter);
		TCB* tcb = entry->data;

		if(tcb->delayed_ack_flag && current > tcb->delayed_ack_timeout) {
			Packet* packet = packet_create(tcb, ACK, NULL, 0);
			if(!packet)
				continue;

			if(!packet_out(tcb, packet, 0))
				continue;

			tcb->delayed_ack_flag = false;
		}
	}

	return true;
}

static bool tcp_try_connect(void* context) {
	TCB* tcb = (TCB*)context;
	uint64_t mac = arp_get_mac(tcb->nic, tcb->dip, tcb->sip);
	
	if(tcb->syn_counter++ == 3) {
		tcb->state = TCP_CLOSED;
		tcb_destroy(tcb);

		return false;
	}

	if(mac != 0xffffffffffff) {
		tcb->dmac = mac;

		if(!nic_output_available(tcb->nic))
			return true;

		Packet* packet = packet_create(tcb, SYN, NULL, 0);
		if(!packet)
			return true;

		if(!packet_out(tcb, packet, 0))
			return true;

		tcb->state = TCP_SYN_SENT;
		tcb->sequence += 1;

		return false;
	}

	return true;
}

static bool time_wait_timer(void* context) {
	TCB* tcb = (TCB*)context;

	tcb->state = TCP_CLOSED;
	tcb_destroy(tcb);

	return false;
}

static bool process_closed(TCB* tcb, Packet* in_packet) {
	printf("connection is closed\n");

	return true;
}

static bool process_syn_sent(TCB* tcb, Packet* in_packet) {
	Ether* ether = (Ether*)(in_packet->buffer + in_packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	//printf("proc syn_sent\n");
	if(tcp->syn == 1 && tcp->ack == 1) {
		tcb->acknowledgement = endian32(tcp->sequence) + 1;
		tcb->last_ack = endian32(tcp->ack);

		tcb->snd_wnd_max = endian16(tcp->window);
		tcb->snd_wnd_cur = 0;

		if(tcp->offset > 5) {
			uint8_t* option = (uint8_t*)tcp->payload;
			uint8_t* data = (uint8_t*)((uint32_t*)tcp + tcp->offset);

			while(option < data) {
				switch(*option) {
					case 0:
						option++;
						break;
					case 1:
						option++;
						break;
					case 2:
						option += 2;
						tcb->snd_mss = endian16(*(uint16_t*)option);
						option += 2;

						if(tcb->snd_mss > 1460)	// cause our driver doesn't support TSO.
							tcb->snd_mss = 1460;
						break;
					case 3:
						option += 2;
						tcb->snd_wnd_scale = 1 << *option;
						option++;
						break;
					default:
						option += *(option + 1);
						break;
				}
			}
		}

		Packet* tmp_packet = packet_create(tcb, ACK, NULL, 0);
		if(!tmp_packet) {
			return false;
		}

		if(!packet_out(tcb, tmp_packet, 0)) {
			return false;
		}

		//for congestion control - slow start
		if(tcb->snd_mss > 2190)
			tcb->cwnd = 2 * tcb->snd_mss;
		else if(1095 < tcb->snd_mss && tcb->snd_mss <= 2190)
			tcb->cwnd = 3 * tcb->snd_mss;
		else if(0 < tcb->snd_mss && tcb->snd_mss <= 1095)
			tcb->cwnd = 4 * tcb->snd_mss;

		tcb->ssthresh = 10000000;//65535;
		tcb->state = TCP_ESTABLISHED;
		uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);
		tcb->connected(tcb_key, tcb->dip, tcb->dport, tcb->context);

	} else if (tcp->rst == 1) {
		tcb->state = TCP_CLOSED;
		tcb_destroy(tcb);
	}

	return true;
}

static bool process_syn_rcvd(TCB* tcb, Packet* in_packet) {
	printf("syn_rcvd\n");

	return true;
}

static bool process_established(TCB* tcb, Packet* in_packet) {
	Ether* ether = (Ether*)(in_packet->buffer + in_packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	if(tcp->ack == 1) {
		uint32_t tmp_ack = endian32(tcp->acknowledgement);

		tcb->snd_wnd_max = endian16(tcp->window) * tcb->snd_wnd_scale;	//TODO: need some condition for sequence num checking

		uint32_t acked_size = tmp_ack - tcb->last_ack;
		
		//need fast retransmssion and handling when acked_size is zero.
		//don't include range when tmp_ack and last_ack are same
		if(tcb->sequence - tmp_ack < tcb->snd_wnd_cur) {
			ListIterator unack_list_iter;
			list_iterator_init(&unack_list_iter, tcb->unack_list);

			if(tcb->cwnd < tcb->ssthresh) {
				if(acked_size >= tcb->snd_mss)
					tcb->cwnd += tcb->snd_mss;
				else
					tcb->cwnd += acked_size;
			} else {
				tcb->cwnd += (tcb->snd_mss * tcb->snd_mss) / tcb->cwnd;
			}

			tcb->last_ack = tmp_ack;

			while(list_iterator_has_next(&unack_list_iter)) {
				Segment* seg = list_iterator_next(&unack_list_iter);

				list_iterator_remove(&unack_list_iter);
				tcb->snd_wnd_cur -= seg->len;

				uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);
				if(tcb->sent) 
					tcb->sent(tcb_key, seg->len, tcb->context);

				nic_free(seg->packet);
				
				if(seg->sequence + seg->len == tmp_ack) {
					gfree(seg);
					break;
				} else {
					gfree(seg);
				}
			}
		}

		uint16_t len = endian16(ip->length) - ip->ihl * 4 - tcp->offset * 4;

		if(len <= 0)
			return true;

		if(tcb->acknowledgement == endian32(tcp->sequence)) {
			tcb->acknowledgement += len;

			if(tcb->delayed_ack_flag) {
				Packet* packet = packet_create(tcb, ACK, NULL, 0);
				if(packet_out(tcb, packet, 0))
					tcb->delayed_ack_flag = false;
			} else {
				tcb->delayed_ack_timeout = timer_ms() + 100;	// 100ms
				tcb->delayed_ack_flag = true;
			}

			uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);

			tcb->received(tcb_key, (uint8_t*)tcp + tcp->offset * 4, len, tcb->context);

			IP* tmp_ip;
			while((tmp_ip = map_remove(tcb->rcv_buffer, (void*)(uintptr_t)tcb->acknowledgement)) != NULL) {
				// reordering out of order packet.
				TCP* tmp_tcp = (TCP*)tmp_ip->body;

				len = endian16(tmp_ip->length) - tmp_ip->ihl * 4 - tmp_tcp->offset * 4;
				tcb->acknowledgement += len;

				if(tcb->delayed_ack_flag) {
					Packet* packet = packet_create(tcb, ACK, NULL, 0);
					if(packet_out(tcb, packet, 0))
						tcb->delayed_ack_flag = false;
				} else {
					tcb->delayed_ack_timeout = timer_ms() + 100;	// 100ms
					tcb->delayed_ack_flag = true;
				}

				uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);
				tcb->received(tcb_key, (uint8_t*)tmp_tcp + tmp_tcp->offset * 4, len, tcb->context);

				gfree(tmp_ip);
			}
		} else if(endian32(tcp->sequence) - tcb->acknowledgement <= tcb->recv_wnd_max) {
			// buffering out of order packet.
			Packet* tmp_packet = packet_create(tcb, ACK, NULL, 0);

			if(!packet_out(tcb, tmp_packet, 0))
				printf("send dup ack fail\n");

			IP* tmp = gmalloc(endian16(ip->length));
			if(!tmp)
				return false;

			memcpy(tmp, ip, endian16(ip->length));

			// TODO:need to limit the out-of-order map size
			if(!map_put(tcb->rcv_buffer, (void*)(uintptr_t)endian32(tcp->sequence), tmp))
				printf("put out-of-order fail\n");
		}
	} else {
		//TODO: no logic decided
	}

	return true;
}

static bool process_listen(TCB* tcb, Packet* in_packet) {
	printf("process_listen\n");

	return true;
}

static bool process_fin_wait_1(TCB* tcb, Packet* in_packet) {
	Ether* ether = (Ether*)(in_packet->buffer + in_packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	if(tcp->fin && tcp->ack) {
		// TODO: simultaneous close
	} else if(tcp->ack) {
		uint32_t tmp_ack = endian32(tcp->acknowledgement);

		tcb->snd_wnd_max = endian16(tcp->window) * tcb->snd_wnd_scale;	//TODO: need some condition
		
		if(tcb->sequence - tmp_ack < tcb->snd_wnd_cur) {
			ListIterator iter;
			list_iterator_init(&iter, tcb->unack_list);

			tcb->last_ack = tmp_ack;

			while(list_iterator_has_next(&iter)) {
				Segment* seg = list_iterator_next(&iter);

				list_iterator_remove(&iter);
				tcb->snd_wnd_cur -= seg->len;

				uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);
				if(tcb->sent)
					tcb->sent(tcb_key, seg->len, tcb->context);

				nic_free(seg->packet);

				if(seg->sequence + seg->len == tmp_ack) {
					gfree(seg);
					break;
				} else {
					gfree(seg);
				}
			}

		}

		uint16_t len = endian16(ip->length) - ip->ihl * 4 - tcp->offset * 4;
		if(len > 0 && tcb->acknowledgement == endian32(tcp->sequence)) {
			tcb->acknowledgement += len;

			if(tcb->delayed_ack_flag) {
				Packet* packet = packet_create(tcb, ACK, NULL, 0);
				if(packet_out(tcb, packet, 0))
					tcb->delayed_ack_flag = false;
			} else {
				tcb->delayed_ack_timeout = timer_ms() + 100;	// 100ms
				tcb->delayed_ack_flag = true;
			}

			uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);
			tcb->received(tcb_key, (uint8_t*)tcp + tcp->offset * 4, len, tcb->context);	// TODO: check last arg(context).
		}

		if(tcb->sequence == endian32(tcp->acknowledgement)) {
			tcb->state = TCP_FIN_WAIT_2;
		}
	}

	return true;
}

static bool process_fin_wait_2(TCB* tcb, Packet* in_packet) {
	Ether* ether = (Ether*)(in_packet->buffer + in_packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	if(tcp->ack) {
		uint32_t tmp_ack = endian32(tcp->acknowledgement);

		tcb->snd_wnd_max = endian16(tcp->window) * tcb->snd_wnd_scale;	//TODO: need some condition

		if(tcb->sequence - tmp_ack < tcb->snd_wnd_cur) {
			ListIterator iter;
			list_iterator_init(&iter, tcb->unack_list);

			tcb->last_ack = tmp_ack;

			while(list_iterator_has_next(&iter)) {
				Segment* seg = list_iterator_next(&iter);

				list_iterator_remove(&iter);
				tcb->snd_wnd_cur -= seg->len;

				uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);
				if(tcb->sent)
					tcb->sent(tcb_key, seg->len, tcb->context);

				nic_free(seg->packet);

				if(seg->sequence + seg->len == tmp_ack) {
					gfree(seg);
					break;
				} else {
					gfree(seg);
				}
			}
		}

		uint16_t len = endian16(ip->length) - ip->ihl * 4 - tcp->offset * 4;
		if(len > 0 && tcb->acknowledgement == endian32(tcp->sequence)) {
			tcb->acknowledgement += len;

			if(tcb->delayed_ack_flag) {
				Packet* packet = packet_create(tcb, ACK, NULL, 0);
				if(packet_out(tcb, packet, 0))
					tcb->delayed_ack_flag = false;
			} else {
				tcb->delayed_ack_timeout = timer_ms() + 100;	// 100ms
				tcb->delayed_ack_flag = true;
			}

			uint64_t tcb_key = tcb_key_create(ip->destination, tcp->destination);
			tcb->received(tcb_key, (uint8_t*)tcp + tcp->offset * 4, len, tcb->context);	// TODO: check last arg(context).
		}

		if(tcp->fin) {
			// TODO: need to send ack about fin 
			tcb->state = TCP_TIME_WAIT;	
			event_timer_add(time_wait_timer, tcb, MSL * 2, MSL);
		}
	}

	return true;
}

static bool process_closing(TCB* tcb, Packet* in_packet) {
	Ether* ether = (Ether*)(in_packet->buffer + in_packet->start);
	IP* ip = (IP*)ether->payload;
	TCP* tcp = (TCP*)ip->body;

	if(tcp->fin) {
		//TODO:fin retransmission
	} else if(tcp->ack) {
		if(tcb->sequence == endian32(tcp->acknowledgement)) {
			tcb->state = TCP_TIME_WAIT;
			event_timer_add(time_wait_timer, tcb, MSL * 2, MSL);
		}
	}

	return true;
}

static bool process_time_wait(TCB* tcb, Packet* in_packet) {
	printf("process_time_wait\n");

	return true;
}

static bool process_close_wait(TCB* tcb, Packet* in_packet) {
	return true;
}

static bool process_last_ack(TCB* tcb, Packet* in_packet) {
	return true;
}
