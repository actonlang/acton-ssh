#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <uv.h>

#define NETCONF_PORT 830
#define BUFFER_SIZE 4096

const char *NETCONF_HELLO = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                           "<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
                           "  <capabilities>\n"
                           "    <capability>urn:ietf:params:netconf:base:1.0</capability>\n"
                           "  </capabilities>\n"
                           "</hello>\n"
                           "]]>]]>";

const char *NETCONF_GET_CONFIG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                                "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"1\">\n"
                                "  <get-config>\n"
                                "    <source>\n"
                                "      <running/>\n"
                                "    </source>\n"
                                "  </get-config>\n"
                                "</rpc>\n"
                                "]]>]]>";

const char *NETCONF_CLOSE_SESSION = "<rpc message-id=\"101\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
                                    "  <close-session/>\n"
                                    "</rpc>\n"
                                    "]]>]]>";

// Buffer management for handling partial reads
typedef struct {
    char data[BUFFER_SIZE * 2];  // Double size to handle partial messages
    size_t length;
} message_buffer_t;

typedef struct {
    ssh_session ssh;
    ssh_channel channel;
    uv_poll_t poll_handle;
    uv_tty_t tty_handle;
    char read_buffer[BUFFER_SIZE];
    char input_buffer[BUFFER_SIZE];
    message_buffer_t message_buffer;
    const char *subsystem;
    void *subsystem_ctx;
    uv_loop_t *loop;
    int state;  // 0: not connected, 1: hello sent, 2: get-config sent, 3: close-session sent
} client_context_t;

void on_ssh_event(uv_poll_t *handle, int status, int events);
void on_stdin_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
void send_hello(client_context_t *context);
void send_get_config(client_context_t *context);
void send_close_session(client_context_t *context);
void process_reply(client_context_t *context, const char *data, size_t len);
void cleanup(client_context_t *context);
void close_walk_cb(uv_handle_t* handle, void* arg);

int init_ssh(client_context_t *context, const char *hostname, const char *username, const char *password) {
    int rc;

    context->ssh = ssh_new();
    if (context->ssh == NULL) {
        fprintf(stderr, "Failed to create SSH session\n");
        return -1;
    }

    ssh_options_set(context->ssh, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(context->ssh, SSH_OPTIONS_USER, username);
    if (context->subsystem && !strcmp(context->subsystem, "netconf")) {
        ssh_options_set(context->ssh, SSH_OPTIONS_PORT, &(int){NETCONF_PORT});
    }

    int verbosity = SSH_LOG_PROTOCOL;
    ssh_options_set(context->ssh, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    printf("Connecting to SSH server %s:%d...\n", hostname, NETCONF_PORT);

    rc = ssh_connect(context->ssh);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", hostname, ssh_get_error(context->ssh));
        ssh_free(context->ssh);
        return -1;
    }

    printf("SSH connection established, authenticating...\n");

    rc = ssh_userauth_password(context->ssh, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Authentication failed: %s\n", ssh_get_error(context->ssh));
        ssh_disconnect(context->ssh);
        ssh_free(context->ssh);
        return -1;
    }

    printf("Authentication successful, opening channel...\n");

    context->channel = ssh_channel_new(context->ssh);
    if (context->channel == NULL) {
        fprintf(stderr, "Failed to create channel\n");
        ssh_disconnect(context->ssh);
        ssh_free(context->ssh);
        return -1;
    }

    rc = ssh_channel_open_session(context->channel);
    if (rc != SSH_OK) {
        fprintf(stderr, "Failed to open channel: %s\n", ssh_get_error(context->ssh));
        ssh_channel_free(context->channel);
        ssh_disconnect(context->ssh);
        ssh_free(context->ssh);
        return -1;
    }

    if (context->subsystem && strlen(context->subsystem) > 0) {
        printf("Channel opened, requesting %s subsystem...\n", context->subsystem);

        rc = ssh_channel_request_subsystem(context->channel, context->subsystem);
        if (rc != SSH_OK) {
            fprintf(stderr, "Failed to request %s subsystem: %s\n", context->subsystem, ssh_get_error(context->ssh));
            ssh_channel_close(context->channel);
            ssh_channel_free(context->channel);
            ssh_disconnect(context->ssh);
            ssh_free(context->ssh);
            return -1;
        }

        printf("%s subsystem established\n", context->subsystem);

        if (!strcmp("netconf", context->subsystem)) {
            printf("Sending NETCONF hello message...\n");
            send_hello(context);
        }
    } else {
        rc = ssh_channel_request_shell(context->channel);
        if (rc != SSH_OK) {
            fprintf(stderr, "Failed to request shell: %s\n", ssh_get_error(context->ssh));
            ssh_channel_close(context->channel);
            ssh_channel_free(context->channel);
            ssh_disconnect(context->ssh);
            ssh_free(context->ssh);
            return -1;
      }
        printf("Shell successfully acquired\n");
    }

    return 0;
}

// Setup stdin input handling for interactive shell
int setup_stdin(client_context_t *context) {
    if (context->subsystem) {
        // Skip stdin setup for subsystem sessions
        return 0;
    }

    int rc = uv_tty_init(context->loop, &context->tty_handle, 0, 1);
    if (rc != 0) {
        fprintf(stderr, "Failed to initialize TTY: %s\n", uv_strerror(rc));
        return -1;
    }

    context->tty_handle.data = context;

    rc = uv_read_start((uv_stream_t*)&context->tty_handle, alloc_buffer, on_stdin_read);
    if (rc != 0) {
        fprintf(stderr, "Failed to start reading from stdin: %s\n", uv_strerror(rc));
        return -1;
    }

    return 0;
}

// Setup libuv poll for SSH socket
int setup_poll(client_context_t *context) {
    int socket_fd = ssh_get_fd(context->ssh);
    if (socket_fd < 0) {
        fprintf(stderr, "Failed to get SSH socket file descriptor\n");
        return -1;
    }

    // Initialize poll handle
    uv_poll_init(context->loop, &context->poll_handle, socket_fd);
    context->poll_handle.data = context;

    // Start polling for read events
    uv_poll_start(&context->poll_handle, UV_READABLE, on_ssh_event);

    return 0;
}

// Callback for SSH socket events
void on_ssh_event(uv_poll_t *handle, int status, int events) {
    client_context_t *context = (client_context_t *)handle->data;

    if (status < 0) {
        fprintf(stderr, "Poll error: %s\n", uv_strerror(status));
        return;
    }

    if (events & UV_READABLE) {
        int nbytes = ssh_channel_read_nonblocking(context->channel, context->read_buffer, BUFFER_SIZE - 1, 0);
        if (nbytes > 0) {
            context->read_buffer[nbytes] = '\0';
            printf("\nDEBUG: Raw data received (%d bytes):\n", nbytes);
            printf("----------------------------------------\n");
            printf("%s\n", context->read_buffer);
            printf("----------------------------------------\n\n");

            // Append to our message buffer
            if (context->message_buffer.length + nbytes < sizeof(context->message_buffer.data) - 1) {
                memcpy(context->message_buffer.data + context->message_buffer.length,
                       context->read_buffer, nbytes);
                context->message_buffer.length += nbytes;
                context->message_buffer.data[context->message_buffer.length] = '\0';

                // Now process the accumulated buffer
                process_reply(context, context->message_buffer.data, context->message_buffer.length);

                // If we found the delimiter, we can clear the buffer for the next message
                if (strstr(context->message_buffer.data, "]]>]]>") != NULL) {
                    context->message_buffer.length = 0;
                }
            } else {
                fprintf(stderr, "Message buffer overflow, resetting\n");
                context->message_buffer.length = 0;
            }
        } else if (nbytes == SSH_ERROR) {
            fprintf(stderr, "Error reading from channel: %s\n", ssh_get_error(context->ssh));
        } else if (nbytes == SSH_AGAIN || nbytes == 0) {
            printf("No data on the channel\n");
        } else if (ssh_channel_is_eof(context->channel)) {
            fprintf(stderr, "Server closed the connection\n");
            uv_poll_stop(&context->poll_handle);
        }
    }
}

void send_hello(client_context_t *context) {
    printf("Sending NETCONF hello message...\n");

    int rc = ssh_channel_write(context->channel, NETCONF_HELLO, strlen(NETCONF_HELLO));
    if (rc != (int)strlen(NETCONF_HELLO)) {
        fprintf(stderr, "Failed to send hello message: %s\n", ssh_get_error(context->ssh));
        return;
    }

    client_context_t *netconf_ctx = context->subsystem_ctx;
    netconf_ctx->state = 2;
}

void send_get_config(client_context_t *context) {
    printf("Sending NETCONF get-config message...\n");

    int rc = ssh_channel_write(context->channel, NETCONF_GET_CONFIG, strlen(NETCONF_GET_CONFIG));
    if (rc != (int)strlen(NETCONF_GET_CONFIG)) {
        fprintf(stderr, "Failed to send get-config message: %s\n", ssh_get_error(context->ssh));
        return;
    }

    client_context_t *netconf_ctx = context->subsystem_ctx;
    netconf_ctx->state = 2;
}

void send_close_session(client_context_t *context) {
    printf("Sending NETCONF close-session message...\n");

    int rc = ssh_channel_write(context->channel, NETCONF_CLOSE_SESSION, strlen(NETCONF_CLOSE_SESSION));
    if (rc != (int)strlen(NETCONF_CLOSE_SESSION)) {
        fprintf(stderr, "Failed to send close-session message: %s\n", ssh_get_error(context->ssh));
        return;
    }

    client_context_t *netconf_ctx = context->subsystem_ctx;
    netconf_ctx->state = 3;
}

// Process NETCONF reply
void process_reply(client_context_t *context, const char *data, size_t len) {
    if (context->subsystem && !strcmp(context->subsystem, "netconf")) {
        client_context_t *netconf_ctx = context->subsystem_ctx;
        printf("Processing NETCONF reply (%zu bytes)\n", len);

        // Check for the end of message delimiter
        if (strstr(data, "]]>]]>") != NULL) {
            printf("Found NETCONF message delimiter\n");

            if (netconf_ctx->state == 1) {
                // Already sent hello, now send get-config
                printf("Received server response after our hello, sending get-config\n");
                send_get_config(context);
            } else if (netconf_ctx->state == 2) {
                // Received get-config reply, now send close-session
                printf("Get-config completed successfully, closing session...\n");

                // TODO do something with retreived data?

                // Send close-session to gracefully terminate the NETCONF session
                send_close_session(context);
            } else if (netconf_ctx->state == 3) {
                // Received close-session reply, we're done
                printf("NETCONF session closed gracefully\n");

                // Stop polling and prepare to exit
                uv_poll_stop(&context->poll_handle);
                uv_stop(context->loop);
            }
        } else {
            printf("INFO: No NETCONF message delimiter found in the response, expecting more data\n");
            // It's possible we received a partial message, which is normal in async I/O
            // We will accumulate more data on subsequent reads
        }
    }
}

// Buffer allocation callback for libuv
void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    client_context_t *context = (client_context_t *)handle->data;
    buf->base = context->input_buffer;
    buf->len = sizeof(context->input_buffer);
}

// Handle stdin input and forward to SSH channel
void on_stdin_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    client_context_t *context = (client_context_t *)stream->data;

    if (nread < 0) {
        if (nread == UV_EOF) {
            printf("EOF received from stdin\n");
            uv_stop(context->loop);
        } else {
            fprintf(stderr, "Error reading from stdin: %s\n", uv_strerror(nread));
        }
        return;
    }

    if (nread > 0) {
        int rc = ssh_channel_write(context->channel, buf->base, nread);
        if (rc != nread) {
            fprintf(stderr, "Failed to write to SSH channel: %s\n", ssh_get_error(context->ssh));
        }
    }
}

// Cleanup resources
void cleanup(client_context_t *context) {
    // Stop polling if still active
    uv_poll_stop(&context->poll_handle);

    // Stop stdin reading if active
    if (!context->subsystem) {
        uv_read_stop((uv_stream_t*)&context->tty_handle);
        uv_close((uv_handle_t*)&context->tty_handle, NULL);
    }

    // Close the poll handle (needs to be closed before the loop can be closed properly)
    uv_close((uv_handle_t*)&context->poll_handle, NULL);

    // Close SSH channel if it exists
    if (context->channel) {
        ssh_channel_close(context->channel);
        ssh_channel_free(context->channel);
    }

    // Close SSH session if it exists
    if (context->ssh) {
        ssh_disconnect(context->ssh);
        ssh_free(context->ssh);
    }
}

int main(int argc, char *argv[]) {
    int r = 0;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s <hostname> <username> <password> [subsystem]\n", argv[0]);
        return 1;
    }

    const char *hostname = argv[1];
    const char *username = argv[2];
    const char *password = argv[3];
    const char *subsystem = NULL;

    if (argc == 5) {
        subsystem = argv[4];
    }

    uv_loop_t loop;
    uv_loop_init(&loop);

    client_context_t context = {0};
    context.subsystem = subsystem;
    if (subsystem && !strcmp(subsystem, "netconf")) {
        context.subsystem_ctx = &((client_context_t){0});
    }
    context.loop = &loop;
    context.message_buffer.length = 0;

    if (init_ssh(&context, hostname, username, password) < 0) {
        uv_loop_close(&loop);
        return 1;
    }

    // Setup polling for SSH socket
    if (setup_poll(&context) < 0) {
        cleanup(&context);
        uv_loop_close(&loop);
        return 1;
    }

    // Setup stdin input handling for shell sessions
    if (setup_stdin(&context) < 0) {
        cleanup(&context);
        uv_loop_close(&loop);
        return 1;
    }

    if (subsystem) {
        if (!strcmp(subsystem, "netconf")) {
            printf("Connected to NETCONF server at %s and sent hello\n", hostname);
        } else {
            printf("Connected to %s server at %s\n", subsystem, hostname);
        }
        printf("Waiting for server response...\n");
    } else {
        printf("Connected to SSH server at %s\n", hostname);
        printf("Ready for input\n");
    }

    uv_run(&loop, UV_RUN_DEFAULT);

    cleanup(&context);

    // Walk the loop to close any remaining handles
    uv_walk(&loop, (uv_walk_cb)close_walk_cb, NULL);

    // Run the loop one more time to let close callbacks execute
    do {
        r = uv_run(&loop, UV_RUN_DEFAULT);
    } while (r != 0);

    // Now it's safe to close the loop
    r = uv_loop_close(&loop);
    if (r != 0) {
        fprintf(stderr, "WARNING: Loop close failed: %s\n", uv_strerror(r));

        // If we still have handles, print debug info
        if (r == UV_EBUSY) {
            fprintf(stderr, "There are still active handles in the loop. This is a leak.\n");
        }
    }

    return 0;
}

// Walk callback to close remaining handles
void close_walk_cb(uv_handle_t* handle, void* arg) {
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
}
