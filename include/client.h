//
// Created by reece-melnick on 11/2/24.
//

#ifndef CLIENT_H
#define CLIENT_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void parseCommandLine(int argc, char *argv[], char **message, char **function);
static void setup_network_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *address, in_port_t port, int *err);
static int  connect_to_server(struct sockaddr_storage *addr, socklen_t addr_len, int *err);
void        usage(void);
static int  validate_filter_function(char const *function, int *err);

#endif    // CLIENT_H
