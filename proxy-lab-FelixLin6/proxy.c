/*
 * Starter code for proxy lab.
 * Feel free to modify this code in whatever way you wish.
 */

/* Some useful includes to help you get started */

#include "csapp.h"
#include "http_parser.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * Debug macros, which can be enabled by adding -DDEBUG in the Makefile
 * Use these if you find them useful, or delete them if not
 */
#ifdef DEBUG
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dbg_assert(...)
#define dbg_printf(...)
#endif

/*
 * Max cache and object sizes
 * You might want to move these to the file containing your cache implementation
 */
#define MAX_CACHE_SIZE (1024 * 1024)
#define MAX_OBJECT_SIZE (100 * 1024)

/*
 * String to use for the User-Agent header.
 * Don't forget to terminate with \r\n
 */
static const char *header_user_agent = "Mozilla/5.0"
                                       " (X11; Linux x86_64; rv:3.10.0)"
                                       " Gecko/20220411 Firefox/63.0.1";

void sigpipe_handler(int sig);
void clienterror(int fd, const char *errnum, const char *shortmsg,
                 const char *longmsg);

// From tiny.c
void clienterror(int fd, const char *errnum, const char *shortmsg,
                 const char *longmsg) {
    char buf[MAXLINE];
    char body[MAXBUF];
    size_t buflen;
    size_t bodylen;

    /* Build the HTTP response body */
    bodylen = snprintf(body, MAXBUF,
                       "<!DOCTYPE html>\r\n"
                       "<html>\r\n"
                       "<head><title>Tiny Error</title></head>\r\n"
                       "<body bgcolor=\"ffffff\">\r\n"
                       "<h1>%s: %s</h1>\r\n"
                       "<p>%s</p>\r\n"
                       "<hr /><em>The Tiny Web server</em>\r\n"
                       "</body></html>\r\n",
                       errnum, shortmsg, longmsg);
    if (bodylen >= MAXBUF) {
        return; // Overflow!
    }

    /* Build the HTTP response headers */
    buflen = snprintf(buf, MAXLINE,
                      "HTTP/1.0 %s %s\r\n"
                      "Content-Type: text/html\r\n"
                      "Content-Length: %zu\r\n\r\n",
                      errnum, shortmsg, bodylen);
    if (buflen >= MAXLINE) {
        return; // Overflow!
    }

    /* Write the headers */
    if (rio_writen(fd, buf, buflen) < 0) {
        fprintf(stderr, "Error writing error response headers to client\n");
        return;
    }

    /* Write the body */
    if (rio_writen(fd, body, bodylen) < 0) {
        fprintf(stderr, "Error writing error response body to client\n");
        return;
    }
}

void run_session(int connfd) {
    rio_t rio;
    rio_readinitb(&rio, connfd);

    parser_t *parser = parser_new();
    char buf[PARSER_MAXLINE];
    if (!rio_readlineb(&rio, buf, sizeof(buf)) ||
        parser_parse_line(parser, buf) != REQUEST) {
        parser_free(parser);
        return;
    }

    while (rio_readlineb(&rio, buf, PARSER_MAXLINE) > 0) {
        if (!strcmp(buf, "\r\n"))
            break;
        if (parser_parse_line(parser, buf) == ERROR) {
            parser_free(parser);
            return;
        }
    }

    const char *method, *path, *host, *sport;
    int port = 80;
    parser_retrieve(parser, METHOD, &method);
    parser_retrieve(parser, PATH, &path);
    parser_retrieve(parser, HOST, &host);

    // If any of method, path, or host are invalid, then the request is too.
    if (!method || !path || !host) {
        clienterror(connfd, "400", "Bad Request", "Bad request.");
        parser_free(parser);
        return;
    }

    if (strcmp(method, "GET")) {
        clienterror(connfd, "501", "Not Implemented",
                    "This proxy only supports GET.");
        parser_free(parser);
        return;
    }

    if (parser_retrieve(parser, PORT, &sport) == 0 && sport)
        port = atoi(sport);

    char portstr[8];
    sprintf(portstr, "%d", port);

    header_t *ch = parser_lookup_header(parser, "Host");
    char host_line[MAXLINE];

    // If there was a Host header, use that. If not, assemble a host header with
    // port specifed (or not when the port is default number) into host_line.
    if (ch && ch->value)
        snprintf(host_line, sizeof(host_line), "Host: %s\r\n", ch->value);

    else {
        if (port == 80)
            snprintf(host_line, sizeof(host_line), "Host: %s\r\n", host);
        else
            snprintf(host_line, sizeof(host_line), "Host: %s:%s\r\n", host,
                     portstr);
    }

    char cache_req[MAXLINE];
    if (port == 80)
        snprintf(cache_req, sizeof(cache_req), "http://%s%s", host, path);
    else
        snprintf(cache_req, sizeof(cache_req), "http://%s:%d%s", host, port,
                 path);

    // Look for the client req in the cache.
    char *obj;
    size_t objsize;
    if (get(cache_req, &obj, &objsize)) {
        rio_writen(connfd, obj, objsize);
        free(obj);
        parser_free(parser);
        return;
    }

    char request[MAXBUF];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.0\r\n"
             "%s"
             "User-Agent: %s\r\n"
             "Connection: close\r\n"
             "Proxy-Connection: close\r\n",
             path, host_line, header_user_agent);

    // Assemble parsed headers from client into a req for the server.
    for (header_t *head = parser_retrieve_next_header(parser); head;
         head = parser_retrieve_next_header(parser)) {
        if (!head->name || !*head->name || !head->value)
            continue;

        if (!strcasecmp(head->name, "Host") ||
            !strcasecmp(head->name, "User-Agent") ||
            !strcasecmp(head->name, "Connection") ||
            !strcasecmp(head->name, "Proxy-Connection")) {
            continue;
        }

        char line[MAXLINE];
        int ln =
            snprintf(line, sizeof(line), "%s: %s\r\n", head->name, head->value);
        if (ln < 0 || (size_t)ln >= sizeof(line)) {
            clienterror(connfd, "400", "Bad Request", "Malformed header line.");
            parser_free(parser);
            return;
        }

        strcat(request, line);
    }
    strcat(request, "\r\n");

    int serverfd = open_clientfd(host, portstr);

    rio_t srio;
    rio_readinitb(&srio, serverfd);

    size_t req_len = strlen(request);
    if (rio_writen(serverfd, request, req_len) < 0) {
        close(serverfd);
        parser_free(parser);
        return;
    }

    char returnbuf[MAXBUF];
    char object[MAX_OBJECT_SIZE];
    size_t len = 0;
    size_t written_len = 0;
    size_t n = 0;
    bool over = false;

    // Write back the server's respose into the session with the client.
    // "over" tracks if we read too big of a response. We don't cache resposnes
    // that are too big or else it affects the functioning of the cache b/c of
    // limited space.
    while ((n = rio_readnb(&srio, returnbuf, sizeof(returnbuf))) > 0) {
        if (rio_writen(connfd, returnbuf, n) < 0)
            break;

        written_len += n;
        if (!over && written_len <= MAX_OBJECT_SIZE) {
            memcpy(object + len, returnbuf, n);
            len += n;
        } else
            over = true;
    }

    if (!over && len > 0 && len <= MAX_OBJECT_SIZE) {
        put(cache_req, object, len);
    }

    close(serverfd);
    parser_free(parser);
}

void *thread(void *vargp) {
    int fd = *((int *)vargp);
    pthread_detach(pthread_self());
    free(vargp);
    run_session(fd);
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {

    init_cache();

    int listening_port = atoi(argv[1]);
    if (listening_port <= 1024 || listening_port >= 32768) {
        perror("Invalid port number for listening port\n");
        return 1;
    }

    Signal(SIGPIPE, sigpipe_handler);

    int listenfd, *fd;
    pthread_t tid;

    listenfd = open_listenfd(argv[1]);
    while (1) {
        fd = malloc(sizeof(int));
        *fd = accept(listenfd, NULL, NULL);
        pthread_create(&tid, NULL, thread, fd);
    }

    free_cache();
    return 0;
}

void sigpipe_handler(int sig) {}