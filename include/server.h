//
// Created by reece-melnick on 11/2/24.
//

#ifndef SERVER_H
#define SERVER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void setup_network_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *address, in_port_t port, int *err);
static int  accept_connection(const struct sockaddr_storage *addr, socklen_t addr_len, int backlog, int *err);
int         open_network_socket_server(const char *address, in_port_t port, int backlog, int *err);
void        handle_client(int client_fd, char *buffer, size_t bufsize, int *err);
void        handle_sigint(int sig);
char        upper_filter(char c);
char        lower_filter(char c);
char        null_filter(char c);
char       *transform(char *c, char (*transformation)(char));
void        handleFilterArgument(char const *function, char (**transform_func)(char));

#endif    // SERVER_H
