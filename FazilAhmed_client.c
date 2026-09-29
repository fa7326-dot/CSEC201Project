#include <stdio.h>
#include <string.h>
#include <winsock2.h>

@author mazen ali 426001284

int main(void) {
    /* Initialize the windows socket environment before executing network operations */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Create a transmission control protocol socket and connect to the local server port */
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sock, (struct sockaddr*)&server, sizeof(server));
    char buf[1024];

    /* Send the start packet to establish the unencrypted protocol session */
    send(sock, "(SS,RFMP,v1.0,0)", 16, 0);
    recv(sock, buf, sizeof(buf), 0);

    