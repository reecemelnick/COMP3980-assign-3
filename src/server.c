//
// Created by reece-melnick on 10/29/24.
//

#include "server.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int const  LOWERCASE_MIN     = 96;
static int const  LOWERCASE_MAX     = 123;
static char const DISTANCE_TO_OTHER = 32;
static int const  UPPERCASE_MIN     = 64;
static int const  UPPERCASE_MAX     = 91;
// static const unsigned int SLEEP_T           = 3;

static volatile int keepRunning = 1;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

int main(void)
{
    const char     *address = "127.0.0.1";
    const in_port_t port    = 8080;
    const int       backlog = 5;
    int             err     = 0;

    int server_fd;

    signal(SIGINT, handle_sigint);

    server_fd = open_network_socket_server(address, port, backlog, &err);

    if(server_fd == -1)
    {
        err = errno;
        return 1;
    }

    return 0;
}

int open_network_socket_server(const char *address, in_port_t port, int backlog, int *err)
{
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    int                     client_fd;

    setup_network_address(&addr, &addr_len, address, port, err);

    if(*err != 0)
    {
        client_fd = -1;
        *err      = errno;
        goto done;
    }

    client_fd = accept_connection(&addr, addr_len, backlog, err);

done:
    return client_fd;
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

static int accept_connection(const struct sockaddr_storage *addr, socklen_t addr_len, int backlog, int *err)
{
    int          server_fd;
    ssize_t      result;
    const size_t bufsize = 2048;
    char        *buffer;
    pid_t        pid;
    static int   process_count = 0;
    int          client_fd;
    int          opt = 1;

    buffer = (char *)malloc(bufsize);
    if(buffer == NULL)
    {
        *err = errno;
        return -1;
    }

    server_fd = socket(addr->ss_family, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)

    if(server_fd == -1)
    {
        fprintf(stderr, "SOCKET FAIL: %s\n", strerror(errno));
        *err = errno;
        free(buffer);
        return -1;
    }

    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        fprintf(stderr, "SETSOCKOPT FAIL: %s\n", strerror(errno));
        close(server_fd);
        *err = errno;
        free(buffer);
        return -1;
    }

    result = bind(server_fd, (const struct sockaddr *)addr, addr_len);

    if(result == -1)
    {
        fprintf(stderr, "BIND FAIL: %s\n", strerror(errno));
        close(server_fd);
        *err = errno;
        free(buffer);
        return -1;
    }

    result = listen(server_fd, backlog);

    if(result == -1)
    {
        fprintf(stderr, "LISTEN FAIL: %s\n", strerror(errno));
        close(server_fd);
        free(buffer);
        return -1;
    }

    fcntl(server_fd, F_SETFL, O_NONBLOCK);
    while(1)
    {
        client_fd = accept(server_fd, NULL, 0);

        if(keepRunning == 0)
        {
            printf("Stopping server...\n");
            while(process_count > 0)
            {
                if(waitpid(-1, NULL, 0) > 0)
                {
                    printf("Cleaning up proceses...\n");
                    process_count--;
                    printf("Process Count: %d\n", process_count);
                }
            }
            goto done;
        }

        while(waitpid(-1, NULL, WNOHANG) > 0)
        {
            process_count--;
            printf("Destroyed process. Process Count: %d\n", process_count);
        }

        if(client_fd == -1)
        {
            continue;
        }

        pid = fork();
        if(pid < 0)
        {
            close(client_fd);
            *err = errno;
        }
        else if(pid == 0)
        {
            printf("Running process with PID: %d\n", getpid());
            close(server_fd);
            handle_client(client_fd, buffer, bufsize, err);
            close(client_fd);
            free(buffer);
            exit(EXIT_SUCCESS);
        }
        else
        {
            close(client_fd);
            process_count++;
            printf("Process Count: %d\n", process_count);
        }
    }

done:
    free(buffer);
    close(server_fd);
    return client_fd;
}

void handle_sigint(int sig)
{
    if(sig == SIGINT)
    {
        keepRunning = 0;
    }
}

void handle_client(int client_fd, char *buffer, size_t bufsize, int *err)
{
    ssize_t bytes_received;
    size_t  message_len = 0;
    size_t  filter_len  = 0;
    size_t  filter_start;
    char (*transform_func)(char) = null_filter;
    ssize_t result;

    char *message = NULL;
    char *filter  = NULL;

    //    sleep(SLEEP_T);

    bytes_received = read(client_fd, buffer, bufsize - 1);
    if(bytes_received < 0)
    {
        perror("read");
        *err = errno;
    }
    else if(bytes_received == 0)
    {
        printf("Client disconnected.\n");
    }
    else
    {
        buffer[bytes_received] = '\0';

        while(buffer[message_len] != '|' && buffer[message_len] != '\0')
        {
            message_len++;
        }

        filter_start = message_len + 1;

        while(buffer[filter_start + filter_len] != '\0')
        {
            filter_len++;
        }

        message = (char *)malloc((message_len + 1) * sizeof(char));

        if(message == NULL)
        {
            *err = errno;
            goto done;
        }

        filter = (char *)malloc((filter_len + 1) * sizeof(char));

        if(filter == NULL)
        {
            *err = errno;
            goto done;
        }

        strncpy(message, buffer, message_len);
        message[message_len] = '\0';

        strncpy(filter, buffer + filter_start, filter_len);
        filter[filter_len] = '\0';

        handleFilterArgument(filter, &transform_func);
        printf("Transforming Message: %s\n", message);
        transform(message, transform_func);

        result = write(client_fd, message, message_len);
        if(result < 0)
        {
            perror("write");
            *err = errno;
        }
    }
done:
    free(message);
    free(filter);
}

char upper_filter(char c)
{
    if(c > LOWERCASE_MIN && c < LOWERCASE_MAX)
    {
        c = (char)(c - DISTANCE_TO_OTHER);
    }
    return c;
}

char lower_filter(char c)
{
    if(c > UPPERCASE_MIN && c < UPPERCASE_MAX)
    {
        c = (char)(c + DISTANCE_TO_OTHER);
    }
    return c;
}

char null_filter(char c)
{
    return c;
}

char *transform(char *c, char (*transformation)(char))
{
    size_t length;

    if(c == NULL)
    {
        return NULL;
    }

    length = strlen(c);

    for(size_t i = 0; i < length; i++)
    {
        c[i] = transformation(c[i]);
    }

    return c;
}

void handleFilterArgument(char const *function, char (**transform_func)(char))
{
    if(function != NULL)
    {
        if(strcmp(function, "upper") == 0)
        {
            *transform_func = upper_filter;
        }
        else if(strcmp(function, "lower") == 0)
        {
            *transform_func = lower_filter;
        }
        else if(strcmp(function, "null") == 0)
        {
            *transform_func = null_filter;
        }
        else
        {
            perror("Invalid Filter Function");
            exit(EXIT_FAILURE);
        }
    }
}
