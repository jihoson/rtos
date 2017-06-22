#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdbool.h>

#define BUF_LEN 1460

int sock;
unsigned int total;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *bps_checker(void* arg) {
	while(1) {
		pthread_mutex_lock(&lock);
		printf("%u bps\n", total * 8);
		total = 0;
		pthread_mutex_unlock(&lock);
		sleep(1);
	}
}

void *receiver(void* arg) {
	char buff[BUF_LEN + 1];

	while(1) {
		int read_size = read(sock, buff, BUF_LEN);
		pthread_mutex_lock(&lock);
		total += read_size;
		pthread_mutex_unlock(&lock);
	}
}

int main(int argc, char *argv[]) {
	struct sockaddr_in serv_addr;
	char buffer[BUF_LEN + 1];
	int str_len;

	pthread_t thread1;
	pthread_t thread2;

	sock = socket(PF_INET, SOCK_STREAM, 0);

	if(sock == -1) {
		printf("socket error\n");
		return 0;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
		printf("conn error\n");
		return 0;
	}

	if(pthread_create(&thread1, NULL, &bps_checker, NULL) < 0) {
		perror("create thread1 error\n");
		return -1;
	}

	if(pthread_create(&thread2, NULL, &receiver, NULL) < 0) {
		perror("create thread2 error\n");
		return -1;
	}

	memset(buffer, 0xaa, BUF_LEN);
while(1);
	while(1) {
		//usleep(1000);
		write(sock, buffer, BUF_LEN);
	//	send(sock, buffer, BUF_LEN, 0);
		
		/*
		int read_size = read(sock, buffer, BUF_LEN);
		pthread_mutex_lock(&lock);
		total += read_size;
		pthread_mutex_unlock(&lock);
		*/
	}
	close(sock);
	return 0;
}
