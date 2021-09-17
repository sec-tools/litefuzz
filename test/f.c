/*
test crash app #6

buffer overflow in network server
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define BUF_SIZE 64
#define MAX_RECV 128
#define PORT 8080

int main() {
    char buffer[BUF_SIZE] = {0};
    int on = 1;
    struct sockaddr_in serv_addr;

    memset((void*)&serv_addr, 0, sizeof(serv_addr));

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(sock < 0) {
        printf("socket failed\n");
        return -1;
    }

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT);

    if(bind(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) != 0) {
        printf("bind failed\n");
        return -1;
    }

    if(listen(sock, 1) < 0) {
        printf("listen failed\n");
        return -1;
    }

    int conn = accept(sock, (struct sockaddr*)NULL, NULL);

    if(conn < 0) {
        printf("accept failed\n");
        return -1;
    }

    if(recv(conn, buffer, MAX_RECV, 0) < 0) {
        printf("recv failed\n");
        return -1;
    }

    printf("msg -> %s", buffer);

    close(conn);
    close(sock);

    return 0;
}
