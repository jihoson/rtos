#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUF_LEN 1460

unsigned long snd_data;
unsigned long rcv_data;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *bps_checker(void* arg) {
	while(1) {
		printf("snd : %lu, rcv : %lu bps\n", snd_data * 8, rcv_data * 8);
		pthread_mutex_lock(&lock);
		snd_data = 0;
		rcv_data = 0;
		pthread_mutex_unlock(&lock);
		sleep(1);
	}
}

int main(int argc, char *argv[]) {
	char buffer[BUF_LEN + 1];
	struct sockaddr_in server_addr, client_addr;
	char temp[20];
	int server_fd, client_fd;
	int len, msg_size;
	
	pthread_t thread;
	
	if(argc != 2) {
		printf("usage : %s [port]\n", argv[0]);
		exit(0);
	}

	if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)	{
		printf("Server : Can't open stream socket\n");
		exit(0);
	}

	memset(&server_addr, 0x00, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(atoi(argv[1]));

	if(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <0) {
		printf("Server : Can't bind local address.\n");
		exit(0);
	}

	if(listen(server_fd, 5) < 0) {
		printf("Server : Can't listening connect.\n");
		exit(0);
	}

	memset(buffer, 0x00, sizeof(buffer));
	printf("Server : wating connection request.\n");
	len = sizeof(client_addr);

	if(pthread_create(&thread, NULL, &bps_checker, NULL) < 0) {
		perror("create_thread error\n");
		return -1;
	}

	while(1) {
		client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
		if(client_fd < 0) {
			printf("Server: accept failed.\n");
			exit(0);
		}

		inet_ntop(AF_INET, &client_addr.sin_addr.s_addr, temp, sizeof(temp));
		printf("Server : %s client connected.\n", temp);
		
		memset(buffer, 0xff, BUF_LEN);

		while(1) {
			int rcv_size = read(client_fd, buffer, BUF_LEN);
			printf("recv_size : %d\n", rcv_size);
			int snd_size = write(client_fd, buffer, rcv_size);
			pthread_mutex_lock(&lock);
			snd_data += snd_size;
			rcv_data += rcv_size;
			pthread_mutex_unlock(&lock);
		}

		close(client_fd);
		printf("Server : %s client closed.\n", temp);
	}
	close(server_fd);
	return 0;
}
