#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <node_api.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define ERROR_MESSAGE_SIZE 256
#define DEFAULT_CONNECT_TIMEOUT_MS 30000
#define MAX_CONNECT_TIMEOUT_MS 300000

typedef struct {
    char interface_name[IFNAMSIZ];
    char destination_ip[INET_ADDRSTRLEN];
    char source_ip[INET_ADDRSTRLEN];
    int32_t destination_port;
    uint32_t routing_mark;
    uint32_t timeout_ms;
    int socket_fd;
    int error_number;
    char error_message[ERROR_MESSAGE_SIZE];
} connect_options;

typedef struct {
    napi_async_work work;
    napi_deferred deferred;
    connect_options options;
} async_connect_work;

static void set_error(connect_options *options, const char *operation, int error_number) {
    options->error_number = error_number;
    snprintf(
        options->error_message,
        sizeof(options->error_message),
        "%s: %s",
        operation,
        strerror(error_number)
    );
}

static void throw_errno(napi_env env, const char *operation) {
    char message[ERROR_MESSAGE_SIZE];
    snprintf(message, sizeof(message), "%s: %s", operation, strerror(errno));
    napi_throw_error(env, "ERR_TUNDIALER", message);
}

static int is_undefined(napi_env env, napi_value value) {
    napi_valuetype type;
    return napi_typeof(env, value, &type) == napi_ok && type == napi_undefined;
}

static int read_string(
    napi_env env,
    napi_value value,
    char *destination,
    size_t destination_size,
    const char *argument_name,
    int allow_empty
) {
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, value, NULL, 0, &length);
    if (status != napi_ok) {
        char message[ERROR_MESSAGE_SIZE];
        snprintf(message, sizeof(message), "Invalid %s argument", argument_name);
        napi_throw_type_error(env, NULL, message);
        return 0;
    }
    /* napi_get_value_string_utf8 truncates instead of reporting overflow. A
     * truncated interface or address could silently route traffic incorrectly,
     * so reject it explicitly. */
    if (length >= destination_size) {
        char message[ERROR_MESSAGE_SIZE];
        snprintf(message, sizeof(message), "Invalid %s argument: value is too long", argument_name);
        napi_throw_range_error(env, NULL, message);
        return 0;
    }
    status = napi_get_value_string_utf8(env, value, destination, destination_size, &length);
    if (status != napi_ok) {
        char message[ERROR_MESSAGE_SIZE];
        snprintf(message, sizeof(message), "Invalid %s argument", argument_name);
        napi_throw_type_error(env, NULL, message);
        return 0;
    }
    destination[length] = '\0';
    if (!allow_empty && length == 0) {
        char message[ERROR_MESSAGE_SIZE];
        snprintf(message, sizeof(message), "Invalid %s argument: value is required", argument_name);
        napi_throw_type_error(env, NULL, message);
        return 0;
    }
    return 1;
}

static int parse_options(napi_env env, size_t argc, napi_value *args, connect_options *options) {
    memset(options, 0, sizeof(*options));
    options->socket_fd = -1;
    options->timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS;

    if (argc < 3) {
        napi_throw_error(env, NULL, "Usage: connect(iface, destinationIp, port, routingMark?, sourceIp?, timeoutMs?)");
        return 0;
    }
    if (!read_string(env, args[0], options->interface_name, sizeof(options->interface_name), "iface", 0)) return 0;
    if (!read_string(env, args[1], options->destination_ip, sizeof(options->destination_ip), "destinationIp", 0)) return 0;

    if (napi_get_value_int32(env, args[2], &options->destination_port) != napi_ok) {
        napi_throw_type_error(env, NULL, "Invalid port argument");
        return 0;
    }
    if (options->destination_port < 1 || options->destination_port > 65535) {
        napi_throw_range_error(env, NULL, "Port must be between 1 and 65535");
        return 0;
    }
    if (if_nametoindex(options->interface_name) == 0) {
        throw_errno(env, "if_nametoindex() failed");
        return 0;
    }

    if (argc >= 4 && !is_undefined(env, args[3])) {
        if (napi_get_value_uint32(env, args[3], &options->routing_mark) != napi_ok) {
            napi_throw_type_error(env, NULL, "Invalid routingMark argument");
            return 0;
        }
    }
    if (argc >= 5 && !is_undefined(env, args[4])) {
        if (!read_string(env, args[4], options->source_ip, sizeof(options->source_ip), "sourceIp", 1)) return 0;
    }
    if (argc >= 6 && !is_undefined(env, args[5])) {
        if (napi_get_value_uint32(env, args[5], &options->timeout_ms) != napi_ok) {
            napi_throw_type_error(env, NULL, "Invalid timeoutMs argument");
            return 0;
        }
        if (options->timeout_ms == 0 || options->timeout_ms > MAX_CONNECT_TIMEOUT_MS) {
            napi_throw_range_error(env, NULL, "timeoutMs must be between 1 and 300000");
            return 0;
        }
    }
    return 1;
}

/* No N-API calls occur below this point. The function may run either on the
 * JavaScript thread for the legacy synchronous API or in libuv's worker pool
 * for connectAsync(). */
static void connect_socket(connect_options *options) {
    options->socket_fd = -1;
    options->error_number = 0;
    options->error_message[0] = '\0';

    struct in_addr destination;
    if (inet_pton(AF_INET, options->destination_ip, &destination) != 1) {
        set_error(options, "inet_pton(destination) failed", EINVAL);
        return;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        set_error(options, "socket() failed", errno);
        return;
    }

    int descriptor_flags = fcntl(fd, F_GETFD, 0);
    if (descriptor_flags >= 0) (void)fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC);

#if defined(SO_BINDTODEVICE)
    /* SO_BINDTODEVICE forces the kernel to use this OpenVPN interface, even
     * when another tunnel or the container's default route is available. */
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, options->interface_name, strlen(options->interface_name)) < 0) {
        int saved_errno = errno;
        close(fd);
        set_error(options, "setsockopt(SO_BINDTODEVICE) failed", saved_errno);
        return;
    }
#else
    close(fd);
    set_error(options, "SO_BINDTODEVICE is unavailable on this platform", ENOTSUP);
    return;
#endif

#if defined(SO_MARK)
    if (options->routing_mark != 0) {
        uint32_t mark = options->routing_mark;
        /* The supervisor owns a separate route table per mark. Marking the
         * socket—not packets globally—keeps parallel tunnel requests isolated.
         */
        if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
            int saved_errno = errno;
            close(fd);
            set_error(options, "setsockopt(SO_MARK) failed", saved_errno);
            return;
        }
    }
#else
    if (options->routing_mark != 0) {
        close(fd);
        set_error(options, "SO_MARK is unavailable on this platform", ENOTSUP);
        return;
    }
#endif

#ifdef IP_UNICAST_IF
    /* This is an extra per-socket output-interface constraint on Linux. The
     * SO_BINDTODEVICE + SO_MARK combination above is authoritative, so an old
     * kernel rejecting this optional hint does not weaken fail-closed routing. */
    uint32_t interface_index = htonl(if_nametoindex(options->interface_name));
    (void)setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, &interface_index, sizeof(interface_index));
#endif

    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

    if (options->source_ip[0] != '\0') {
        struct sockaddr_in local_address;
        memset(&local_address, 0, sizeof(local_address));
        local_address.sin_family = AF_INET;
        if (inet_pton(AF_INET, options->source_ip, &local_address.sin_addr) != 1) {
            close(fd);
            set_error(options, "inet_pton(source) failed", EINVAL);
            return;
        }
        if (bind(fd, (struct sockaddr *)&local_address, sizeof(local_address)) < 0) {
            int saved_errno = errno;
            close(fd);
            set_error(options, "bind(source) failed", saved_errno);
            return;
        }
    }

    int file_flags = fcntl(fd, F_GETFL, 0);
    if (file_flags < 0 || fcntl(fd, F_SETFL, file_flags | O_NONBLOCK) < 0) {
        int saved_errno = errno;
        close(fd);
        set_error(options, "fcntl(O_NONBLOCK) failed", saved_errno);
        return;
    }

    struct sockaddr_in destination_address;
    memset(&destination_address, 0, sizeof(destination_address));
    destination_address.sin_family = AF_INET;
    destination_address.sin_port = htons((uint16_t)options->destination_port);
    destination_address.sin_addr = destination;

    int connect_result = connect(fd, (struct sockaddr *)&destination_address, sizeof(destination_address));
    if (connect_result < 0 && errno != EINPROGRESS && errno != EALREADY) {
        int saved_errno = errno;
        close(fd);
        set_error(options, "connect() failed", saved_errno);
        return;
    }

    if (connect_result < 0) {
        struct pollfd poll_descriptor;
        poll_descriptor.fd = fd;
        poll_descriptor.events = POLLOUT;
        poll_descriptor.revents = 0;
        int poll_result;
        do {
            poll_result = poll(&poll_descriptor, 1, (int)options->timeout_ms);
        } while (poll_result < 0 && errno == EINTR);
        if (poll_result == 0) {
            close(fd);
            set_error(options, "connect() timed out", ETIMEDOUT);
            return;
        }
        if (poll_result < 0) {
            int saved_errno = errno;
            close(fd);
            set_error(options, "poll(connect) failed", saved_errno);
            return;
        }
        int connect_error = 0;
        socklen_t connect_error_size = sizeof(connect_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &connect_error, &connect_error_size) < 0) {
            int saved_errno = errno;
            close(fd);
            set_error(options, "getsockopt(SO_ERROR) failed", saved_errno);
            return;
        }
        if (connect_error != 0) {
            close(fd);
            set_error(options, "connect() failed", connect_error);
            return;
        }
    }

    /* Keep the descriptor nonblocking: Node/libuv expects that when it adopts
     * the already-connected fd as a net.Socket. */
    options->socket_fd = fd;
}

static napi_value create_fd_value(napi_env env, int fd) {
    napi_value value;
    if (napi_create_int32(env, fd, &value) != napi_ok) {
        napi_throw_error(env, NULL, "Unable to create socket descriptor result");
        return NULL;
    }
    return value;
}

static napi_value connect_sync(napi_env env, napi_callback_info info) {
    size_t argc = 6;
    napi_value args[6];
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok) {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    connect_options options;
    if (!parse_options(env, argc, args, &options)) return NULL;
    connect_socket(&options);
    if (options.socket_fd < 0) {
        napi_throw_error(env, "ERR_TUNDIALER", options.error_message[0] ? options.error_message : "Connection failed");
        return NULL;
    }
    return create_fd_value(env, options.socket_fd);
}

static void connect_async_execute(napi_env env, void *data) {
    (void)env;
    async_connect_work *work = (async_connect_work *)data;
    connect_socket(&work->options);
}

static napi_value create_error_value(napi_env env, const connect_options *options) {
    napi_value code;
    napi_value message;
    napi_value error;
    const char *text = options->error_message[0] ? options->error_message : "Asynchronous connection failed";
    if (napi_create_string_utf8(env, "ERR_TUNDIALER", NAPI_AUTO_LENGTH, &code) != napi_ok ||
        napi_create_string_utf8(env, text, NAPI_AUTO_LENGTH, &message) != napi_ok ||
        napi_create_error(env, code, message, &error) != napi_ok) {
        return NULL;
    }
    if (options->error_number != 0) {
        napi_value error_number;
        if (napi_create_int32(env, options->error_number, &error_number) == napi_ok) {
            (void)napi_set_named_property(env, error, "errno", error_number);
        }
    }
    return error;
}

static void connect_async_complete(napi_env env, napi_status status, void *data) {
    async_connect_work *work = (async_connect_work *)data;
    if (status != napi_ok && work->options.socket_fd >= 0) {
        close(work->options.socket_fd);
        work->options.socket_fd = -1;
    }

    if (status != napi_ok || work->options.socket_fd < 0) {
        napi_value error = create_error_value(env, &work->options);
        if (error != NULL) {
            (void)napi_reject_deferred(env, work->deferred, error);
        }
    } else {
        napi_value result = create_fd_value(env, work->options.socket_fd);
        if (result != NULL) {
            (void)napi_resolve_deferred(env, work->deferred, result);
        } else {
            close(work->options.socket_fd);
        }
    }
    napi_delete_async_work(env, work->work);
    free(work);
}

static napi_value connect_async(napi_env env, napi_callback_info info) {
    size_t argc = 6;
    napi_value args[6];
    if (napi_get_cb_info(env, info, &argc, args, NULL, NULL) != napi_ok) {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    async_connect_work *work = calloc(1, sizeof(*work));
    if (work == NULL) {
        napi_throw_error(env, "ENOMEM", "Unable to allocate asynchronous connection state");
        return NULL;
    }
    if (!parse_options(env, argc, args, &work->options)) {
        free(work);
        return NULL;
    }

    napi_value promise;
    if (napi_create_promise(env, &work->deferred, &promise) != napi_ok) {
        free(work);
        napi_throw_error(env, NULL, "Unable to create connection promise");
        return NULL;
    }
    napi_value resource_name;
    if (napi_create_string_utf8(env, "tundialer.connectAsync", NAPI_AUTO_LENGTH, &resource_name) != napi_ok ||
        napi_create_async_work(env, NULL, resource_name, connect_async_execute, connect_async_complete, work, &work->work) != napi_ok) {
        free(work);
        napi_throw_error(env, NULL, "Unable to create asynchronous connection work");
        return NULL;
    }
    if (napi_queue_async_work(env, work->work) != napi_ok) {
        napi_delete_async_work(env, work->work);
        free(work);
        napi_throw_error(env, NULL, "Unable to queue asynchronous connection work");
        return NULL;
    }
    return promise;
}

napi_value init(napi_env env, napi_value exports) {
    napi_property_descriptor descriptors[] = {
        { "connect", NULL, connect_sync, NULL, NULL, NULL, napi_default, NULL },
        { "connectAsync", NULL, connect_async, NULL, NULL, NULL, napi_default, NULL },
    };
    if (napi_define_properties(env, exports, sizeof(descriptors) / sizeof(descriptors[0]), descriptors) != napi_ok) {
        return NULL;
    }
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
