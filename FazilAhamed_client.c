#include <stdio.h>
#include <string.h>
#include <winsock2.h>

int main(void) {
    /* Initialize the windows socket environment before executing network operations */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Create a transmission control protocol socket and connect to the local server port */
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(9999);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sock, (struct sockaddr*)&server, sizeof(server));
    char buf[1024];

    /* Send the start packet to establish the unencrypted protocol session */
    send(sock, "(SS,RFMP,v1.0,0)", 16, 0);
    recv(sock, buf, sizeof(buf), 0);

    /* Prompt the user for a target filename and build the open read command */
    char filename[100];
    char command[150];
    printf("Enter filename: ");
    scanf("%99s", filename);

    sprintf(command, "(CM,openRead,%s)", filename);
    send(sock, command, (int)strlen(command), 0);

    /* Receive the file contents returned from the server and display the output */
    int bytes = recv(sock, buf, sizeof(buf) - 1, 0);
    if (bytes > 0) {
        buf[bytes] = '\0';
        printf("File Output:\n%s\n", buf);
    }

    /* Send the closing packet to terminate the protocol session */
    send(sock, "(End)", 5, 0);

    /* Clean up and shut down the windows socket environment */
    closesocket(sock);
    WSACleanup();
    return 0;
}