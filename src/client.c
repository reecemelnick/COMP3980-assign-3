//
// Created by reece-melnick on 10/29/24.
//

#include "client.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    const char             *address = "127.0.0.1";
    const in_port_t         port    = 8080;
    int                     err     = 0;
    struct sockaddr_storage server_addr;
    socklen_t               server_addr_len;
    int                     client_fd = 1;
    int                     retval;
    char                   *response_buffer;
    ssize_t                 bytes_received;
    char                   *buffer;
    char                   *resultBuffer = NULL;
    int                     parse_iterator;
    const size_t            bufsize = 2048;
    char                   *message;
    char                   *function;
    size_t                  input_length = 0;

    message  = NULL;
    function = NULL;
    buffer   = NULL;

    retval = 0;
    err    = 0;
    errno  = 0;

    parseCommandLine(argc, argv, &message, &function);

    if(validate_filter_function(function, &err) < 0)
    {
        err    = errno;
        retval = -1;
        goto done;
    }

    if(message != NULL && function != NULL)
    {
        input_length += strlen(message);
        input_length += strlen(function);

        buffer = (char *)malloc(input_length + 2);

        if(buffer == NULL)
        {
            err    = errno;
            retval = -2;
            goto done;
        }

        for(size_t i = 0; i < strlen(message); i++)
        {
            buffer[i] = message[i];
        }

        buffer[strlen(message)] = '|';

        parse_iterator = 0;
        for(size_t i = strlen(message) + 1; i < input_length + 1; i++)
        {
            buffer[i] = function[parse_iterator];
            parse_iterator++;
        }

        if(buffer != NULL)
        {
            buffer[input_length + 1] = '\0';
        }

        setup_network_address(&server_addr, &server_addr_len, address, port, &err);
        if(err != 0)
        {
            fprintf(stderr, "Erro*function;r setting up server address: %s\n", strerror(err));
            retval = -3;
            err    = errno;
            goto cleanup;
        }

        client_fd = connect_to_server(&server_addr, server_addr_len, &err);
        if(client_fd == -1)
        {
            fprintf(stderr, "Failed to connect to server: %s\n", strerror(err));
            retval = -4;
            err    = errno;
            goto cleanup;
        }

        printf("Connected to server! Socket FD: %d\n", client_fd);

        if(send(client_fd, buffer, strlen(buffer), 0) == -1)
        {
            err = errno;
            close(client_fd);
            perror("send");
            goto cleanup;
        }

        response_buffer = (char *)malloc(bufsize);

        if(response_buffer == NULL)
        {
            err = errno;
            goto cleanup;
        }

        bytes_received = read(client_fd, response_buffer, bufsize - 1);

        if(bytes_received == -1)
        {
            err = errno;
            close(client_fd);
            goto cleanup;
        }
        else
        {
            close(client_fd);
            response_buffer[bytes_received] = '\0';
            printf("%s\n", response_buffer);
            free(response_buffer);
        }
    }
    else
    {
        goto cleanup;
    }

cleanup:
    free(buffer);
    free(resultBuffer);

done:
    return retval;
}

static void parseCommandLine(int argc, char *argv[], char **message, char **function)
{
    int arg;
    int argcount = 0;

    while((arg = getopt(argc, argv, "m:f:")) != -1)
    {
        switch(arg)
        {
            case 'm':
                *message = optarg;
                argcount++;
                break;
            case 'f':
                *function = optarg;
                argcount++;
                break;
            case '?':
                usage();
                exit(EXIT_FAILURE);
            default:
                printf("default");
                break;
        }
    }

    if(argcount != 2)
    {
        usage();
        exit(EXIT_FAILURE);
    }
}

static int validate_filter_function(char const *function, int *err)
{
    if(function != NULL)
    {
        if(strcmp(function, "upper") == 0 || strcmp(function, "lower") == 0 || strcmp(function, "null") == 0)
        {
            return 0;
        }

        *err = errno;
        usage();
        return -1;
    }
    return -1;
}

void usage(void)
{
    puts("Usage: ./client [-m] [-f]\nOptions:\n\t-m Message\n\t-f Transform function to be called (upper, lower, null)\n");
}

static int connect_to_server(struct sockaddr_storage *addr, socklen_t addr_len, int *err)
{
    int fd;
    int result;

    fd = socket(addr->ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    if(fd == -1)
    {
        *err = errno;
        goto done;
    }

    result = connect(fd, (const struct sockaddr *)addr, addr_len);

    if(result == -1)
    {
        *err = errno;
        close(fd);
        fd = -1;
    }

done:
    printf("Client_fd: %d\n", fd);
    return fd;
}

static void setup_network_address(struct sockaddr_storage *addr, socklen_t *addr_len, const char *address, in_port_t port, int *err)
{
    in_port_t net_port;

    *addr_len = 0;
    net_port  = htons(port);
    memset(addr, 0, sizeof(*addr));

    if(inet_pton(AF_INET, address, &(((struct sockaddr_in *)addr)->sin_addr)) == 1)
    {
        struct sockaddr_in *ipv4_addr;

        ipv4_addr           = (struct sockaddr_in *)addr;
        addr->ss_family     = AF_INET;
        ipv4_addr->sin_port = net_port;
        *addr_len           = sizeof(struct sockaddr_in);
    }
    else if(inet_pton(AF_INET6, address, &(((struct sockaddr_in6 *)addr)->sin6_addr)) == 1)
    {
        struct sockaddr_in6 *ipv6_addr;

        ipv6_addr            = (struct sockaddr_in6 *)addr;
        addr->ss_family      = AF_INET6;
        ipv6_addr->sin6_port = net_port;
        *addr_len            = sizeof(struct sockaddr_in6);
    }
    else
    {
        fprintf(stderr, "%s is not an IPv4 or an IPv6 address\n", address);
        *err = errno;
    }
}
