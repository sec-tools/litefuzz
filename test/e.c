/*
test crash app #5

buffer overflow in network client
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
#define HOST "127.0.0.1"
#define PORT 8080

int main() {
    char buffer[BUF_SIZE] = {0};
    struct sockaddr_in serv_addr, client_addr;

    memset((void*)&serv_addr, 0, sizeof(serv_addr));
    memset((void*)&client_addr, 0, sizeof(client_addr));

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    inet_pton(AF_INET, HOST, &serv_addr.sin_addr);

    if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("connection failed to %s:%d\n", HOST, PORT);
        return -1;
    }

    if(send(sock, buffer, 1, 0) < 0) {
        printf("send failed\n");
        return -1;
    }

    if(recv(sock, buffer, MAX_RECV, 0) < 0) {
        printf("recv failed\n");
        return -1;
    }

    printf("msg -> %s", buffer);

    close(sock);

    return 0;
}
