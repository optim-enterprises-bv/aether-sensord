/* Benchmark scaffolding -- NOT shipped. Accept-loop listener. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9999;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) { perror("bind"); return 1; }
    if (listen(s, 1024) != 0) { perror("listen"); return 1; }
    fprintf(stderr, "listening on 127.0.0.1:%d\n", port);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        char b[64]; ssize_t r = read(c, b, sizeof(b)); (void)r;
        close(c);
    }
}
