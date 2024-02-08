#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>

#include <errno.h>

#include "ubpf.h"
#include "bpfmap.h"

#include "Header.pb-c.h"
#include "Hello.pb-c.h"
#include "Function.pb-c.h"
#include "Table.pb-c.h"
#include "Packet.pb-c.h"
#include "Notify.pb-c.h"

#include "agent.h"
#include "ebpf_consts.h"

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define HEADER_LENGTH 4
#define PIPELINE_STAGES 32

/* Controller Packet header format. */
struct header
{
    uint16_t type;
    uint16_t length;
};

/* Handler function for controller messages */
typedef int (*handler)(void *buffer, struct header *header);

/* Single stage of the execution pipeline for packet processing. */
struct stage
{
    struct ubpf_vm *vm;
    char name[32];
    ubpf_jit_fn exec;
    uint64_t counter; // number of packets that have passed through this stage
};

/* Execution pipeline for packet processing. */
struct stage pipeline[PIPELINE_STAGES] = {0};

/* Agent configuration */
struct agent
{
    int fd;
    tx_packet_fn transmit;
    struct agent_options *options;
} agent;

/* Interrupt signal for terminating the program. */
static sig_atomic_t sigint = 0;

/**
 * @brief Initialise a packet and create the header for a packet of type `type` and length `len`
 *
 * @param type the type of the packet to create
 * @param len the length of the packet excluding the header
 * @return void* the packet with the header as a preamble
 */
void *create_packet(int type, int len)
{
    uint16_t *header = (uint16_t *)malloc(HEADER_LENGTH + len);
    header[0] = htons(type);
    header[1] = htons(len);

    return header;
}

uint64_t bpf_debug(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)
{
    printf("debug: %lu\n", r1);

    return 0;
}

uint64_t bpf_notify(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)
{
    int id = (int)r1;
    void *payload = (void *)r2;
    int len = (int)r3;

    Notify notify = NOTIFY__INIT;

    notify.id = id;
    notify.data.data = payload;
    notify.data.len = len;

    int packet_len = notify__get_packed_size(&notify);
    void *packet = create_packet(HEADER__TYPE__NOTIFY, packet_len);

    notify__pack(&notify, packet + HEADER_LENGTH);

    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    return 0;
}

uint64_t bpf_lookup(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)
{
    int map = (int)r1;
    uint64_t *key = (uint64_t *)r2;
    uint64_t *store = (uint64_t *)r3;

    uintptr_t value;

    uint64_t ret = bpf_lookup_elem(map, key, &value);

    *store = (uint64_t)value;

    return ret;
}

uint64_t bpf_update(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)
{
    return bpf_update_elem(r1, (void *)r2, (void *)r3, r4);
}

uint64_t bpf_delete(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4, uint64_t r5)
{
    return bpf_delete_elem(r1, (void *)r2);
}

/**
 * @brief Send the hello handshake message to the controllerm advertising of connection and providing version and dpid.
 */
void send_hello()
{
    Hello hello = HELLO__INIT;
    hello.version = 1;
    hello.dpid = agent.options->dpid;

    //
    int packet_len = hello__get_packed_size(&hello);
    void *packet = create_packet(HEADER__TYPE__HELLO, packet_len);
    hello__pack(&hello, packet + HEADER_LENGTH);

    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);
    free(packet);
}

int recv_hello(void *buffer, struct header *header)
{
    Hello *hello;

    hello = hello__unpack(NULL, header->length, buffer);
    int len = hello__get_packed_size(hello);
    hello__free_unpacked(hello, NULL);

    return len;
}

int recv_function_add(void *buffer, struct header *header)
{
    FunctionAddRequest *request;

    request = function_add_request__unpack(NULL, header->length, buffer);
    int len = function_add_request__get_packed_size(request);

    FunctionAddReply reply = FUNCTION_ADD_REPLY__INIT;
    reply.status = FUNCTION_ADD_REPLY__FUNCTION_ADD_STATUS__OK;

    // Validate the input
    if (request->index >= PIPELINE_STAGES)
    {
        reply.status = FUNCTION_ADD_REPLY__FUNCTION_ADD_STATUS__INVALID_STAGE;
    }
    else
    {

        // If there is an existing stage in the pipeline at this position free it
        struct stage *stage = &pipeline[request->index];
        if (stage->vm)
        {
            // Destroy the VM for this program
            ubpf_destroy(stage->vm);

            // Clear the previous state of the stage
            memset(stage, 0, sizeof(struct stage));
        }

        // Create the new VM
        stage->vm = ubpf_create();
        strncpy(stage->name, request->name, 32);
        stage->name[31] = '\0';
        ubpf_toggle_bounds_check(stage->vm, false);

        // Register the map functions
        ubpf_register(stage->vm, 1, "bpf_map_lookup_elem", bpf_lookup);
        ubpf_register(stage->vm, 2, "bpf_map_update_elem", bpf_update);
        ubpf_register(stage->vm, 3, "bpf_map_delete_elem", bpf_delete);
        ubpf_register(stage->vm, 31, "bpf_notify", bpf_notify);
        ubpf_register(stage->vm, 32, "bpf_debug", bpf_debug);

        // Load the stage function
        int err;
        char *errmsg;
        err = ubpf_load_elf(stage->vm, request->elf.data, request->elf.len, &errmsg);

        if (err != 0)
        {
            reply.status = FUNCTION_ADD_REPLY__FUNCTION_ADD_STATUS__INVALID_FUNCTION;
            printf("Error message: %s\n", errmsg);
            free(errmsg);
        }
        else
        {
// On x86-64 architectures use the JIT compiler, otherwise fallback to the interpreter
#if __x86_64__
            stage->exec = ubpf_compile(stage->vm, &errmsg);
#endif

            if (stage->exec == NULL)
            {
                reply.status = FUNCTION_ADD_REPLY__FUNCTION_ADD_STATUS__INVALID_FUNCTION;

                printf("Error JIT %s\n", errmsg);
                free(errmsg);
            }
        }
    }

    // Send install reply
    int packet_len = function_add_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__FUNCTION_ADD_REPLY, packet_len);
    function_add_reply__pack(&reply, packet + HEADER_LENGTH);
    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    // Free the resources
    function_add_request__free_unpacked(request, NULL);
    free(packet);

    return len;
}

int recv_function_remove(void *buffer, struct header *header)
{
    FunctionRemoveRequest *request;
    FunctionRemoveReply reply = FUNCTION_REMOVE_REPLY__INIT;

    request = function_remove_request__unpack(NULL, header->length, buffer);
    int len = function_remove_request__get_packed_size(request);

    reply.status = FUNCTION_REMOVE_REPLY__FUNCTION_REMOVE_STATUS__INVALID_STAGE;
    if (request->index <= PIPELINE_STAGES && pipeline[request->index].vm != NULL)
    {
        struct stage *stage = &pipeline[request->index];
        ubpf_destroy(stage->vm);

        // Clear the previous state of the stage
        memset(stage, 0, sizeof(struct stage));

        reply.status = FUNCTION_REMOVE_REPLY__FUNCTION_REMOVE_STATUS__OK;
    }

    int packet_len = function_remove_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__FUNCTION_REMOVE_REPLY, packet_len);
    function_remove_reply__pack(&reply, packet + HEADER_LENGTH);
    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    function_remove_request__free_unpacked(request, NULL);
    free(packet);

    return len;
}

int recv_function_list(void *buffer, struct header *header)
{
    FunctionListRequest *request;
    request = function_list_request__unpack(NULL, header->length, buffer);
    int len = function_list_request__get_packed_size(request);

    // Reply
    FunctionListReply reply = FUNCTION_LIST_REPLY__INIT;
    FunctionListEntry *entries[PIPELINE_STAGES];
    reply.entries = entries;

    int i = 0;
    for (i = 0; i < PIPELINE_STAGES; i++)
    {
        struct stage *stage = &pipeline[i];

        if (stage->vm)
        {
            FunctionListEntry *entry = malloc(sizeof(FunctionListEntry));
            function_list_entry__init(entry);

            entry->name = stage->name;
            entry->index = i;
            entry->counter = stage->counter;

            entries[reply.n_entries++] = entry;
        }
    }

    int packet_len = function_list_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__FUNCTION_LIST_REPLY, packet_len);

    function_list_reply__pack(&reply, packet + HEADER_LENGTH);
    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    // Cleanup
    for (i = 0; i < reply.n_entries; i++)
    {
        free(entries[i]);
    }

    function_list_request__free_unpacked(request, NULL);
    free(packet);

    return len;
}

int recv_tables_list_request(void *buffer, struct header *header)
{
    TablesListRequest *request;
    TablesListReply reply = TABLES_LIST_REPLY__INIT;

    request = tables_list_request__unpack(NULL, header->length, buffer);
    int len = tables_list_request__get_packed_size(request);

    // Reply
    TableDefinition *entries[TABLE_MAX_ENTRIES];

    reply.status = TABLE_STATUS__STAGE_NOT_FOUND;
    reply.entries = entries;

    if (request->index <= PIPELINE_STAGES && pipeline[request->index].vm != NULL)
    {
        char table_name[32] = {0};
        struct table_entry *tab_entry;
        struct stage *stage = &pipeline[request->index];

        int tables = ubpf_get_tables(stage->vm);
        while (bpf_get_next_key(tables, table_name, table_name) == 0)
        {
            bpf_lookup_elem(tables, table_name, &tab_entry);

            TableDefinition *def = malloc(sizeof(TableDefinition));
            table_definition__init(def);

            def->table_name = malloc(strlen(table_name) + 1);
            strcpy(def->table_name, table_name);

            def->table_type = tab_entry->type;
            def->key_size = tab_entry->key_size;
            def->value_size = tab_entry->value_size;
            def->max_entries = tab_entry->max_entries;

            entries[reply.n_entries++] = def;
        }
    }

    int packet_len = tables_list_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__TABLES_LIST_REPLY, packet_len);

    tables_list_reply__pack(&reply, packet + HEADER_LENGTH);

    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    // house keeping
    int i;
    for (i = 0; i < reply.n_entries; i++)
    {
        free(entries[i]->table_name);
        free(entries[i]);
    }

    free(packet);
    tables_list_request__free_unpacked(request, NULL);

    return len;
}

int recv_table_list_request(void *buffer, struct header *header)
{
    TableListRequest *request;
    TableListReply reply = TABLE_LIST_REPLY__INIT;

    request = table_list_request__unpack(NULL, header->length, buffer);
    int len = table_list_request__get_packed_size(request);

    reply.status = TABLE_STATUS__STAGE_NOT_FOUND;

    if (request->index <= PIPELINE_STAGES && pipeline[request->index].vm != NULL)
    {
        struct stage *stage = &pipeline[request->index];

        // Create the key for the lookup
        char table_name[32] = {0};
        strncpy(table_name, request->table_name, 31);
        struct table_entry *tab_entry;

        // Find the table referencing the tables
        int tables = ubpf_get_tables(stage->vm);
        int ret = bpf_lookup_elem(tables, table_name, &tab_entry);

        //
        if (ret == -1)
        {
            reply.status = TABLE_STATUS__TABLE_NOT_FOUND;
        }
        else
        {
            TableDefinition tableEntry = TABLE_DEFINITION__INIT;

            reply.status = TABLE_STATUS__SUCCESS;

            tableEntry.table_name = request->table_name;
            tableEntry.table_type = tab_entry->type;
            tableEntry.key_size = tab_entry->key_size;
            tableEntry.value_size = tab_entry->value_size;
            tableEntry.max_entries = tab_entry->max_entries;

            reply.entry = &tableEntry;

            int item_size;
            unsigned char *items;

            if (tab_entry->type == BPF_MAP_TYPE_HASH)
            {
                item_size = tab_entry->key_size + tab_entry->value_size;
                items = calloc(tab_entry->max_entries, item_size);

                unsigned char *key = items;
                unsigned char *next_key = items;
                unsigned char *value;

                while (bpf_get_next_key(tab_entry->fd, key, next_key) == 0)
                {
                    bpf_lookup_elem(tab_entry->fd, next_key, &value);
                    memcpy(next_key + tab_entry->key_size, value, tab_entry->value_size);

                    reply.n_items++;
                    key = next_key;
                    next_key = items + reply.n_items * item_size;
                }
            }

            else if (tab_entry->type == BPF_MAP_TYPE_ARRAY)
            {
                uint32_t key = 0;
                reply.n_items = tab_entry->max_entries;
                item_size = tab_entry->value_size;

                void *data;
                items = malloc(reply.n_items * item_size);
                bpf_lookup_elem(tab_entry->fd, &key, &data);
                memcpy(items, data, reply.n_items * item_size);
            }

            reply.items.len = reply.n_items * item_size;
            reply.items.data = items;
        }
    }

    int packet_len = table_list_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__TABLE_LIST_REPLY, packet_len);

    table_list_reply__pack(&reply, packet + HEADER_LENGTH);
    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    free(packet);
    free(reply.items.data);
    table_list_request__free_unpacked(request, NULL);

    return len;
}

int recv_table_entry_get_request(void *buffer, struct header *header)
{
    TableEntryGetRequest *request;
    TableEntryGetReply reply = TABLE_ENTRY_GET_REPLY__INIT;

    request = table_entry_get_request__unpack(NULL, header->length, buffer);
    int len = table_entry_get_request__get_packed_size(request);

    reply.status = TABLE_STATUS__STAGE_NOT_FOUND;

    if (request->index <= PIPELINE_STAGES && pipeline[request->index].vm != NULL)
    {
        struct stage *stage = &pipeline[request->index];

        char table_name[32] = {0};
        strncpy(table_name, request->table_name, 31);
        struct table_entry *tab_entry;

        int tables = ubpf_get_tables(stage->vm);
        int ret = bpf_lookup_elem(tables, table_name, &tab_entry);

        if (ret == -1)
        {
            reply.status = TABLE_STATUS__TABLE_NOT_FOUND;
        }
        else
        {
            reply.key = request->key;
            reply.value.len = tab_entry->value_size;

            ret = bpf_lookup_elem(tab_entry->fd, request->key.data, &reply.value.data);

            if (ret == -1)
            {
                reply.status = TABLE_STATUS__ENTRY_NOT_FOUND;
            }
            else
            {
                reply.status = TABLE_STATUS__SUCCESS;
            }
        }
    }

    int packet_len = table_entry_get_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__TABLE_ENTRY_GET_REPLY, packet_len);
    table_entry_get_reply__pack(&reply, packet + HEADER_LENGTH);

    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    free(packet);
    table_entry_get_request__free_unpacked(request, NULL);

    return len;
}

int recv_table_entry_insert_request(void *buffer, struct header *header)
{
    TableEntryInsertRequest *request;
    TableEntryInsertReply reply = TABLE_ENTRY_INSERT_REPLY__INIT;

    request = table_entry_insert_request__unpack(NULL, header->length, buffer);
    int len = table_entry_insert_request__get_packed_size(request);

    reply.status = TABLE_STATUS__STAGE_NOT_FOUND;

    if (request->index <= PIPELINE_STAGES && pipeline[request->index].vm != NULL)
    {
        struct stage *stage = &pipeline[request->index];

        char table_name[32] = {0};
        strncpy(table_name, request->table_name, 31);
        struct table_entry *tab_entry;
        int tables = ubpf_get_tables(stage->vm);
        int ret = bpf_lookup_elem(tables, table_name, &tab_entry);

        if (ret == -1)
        {
            reply.status = TABLE_STATUS__TABLE_NOT_FOUND;
        }
        else
        {
            ret = bpf_update_elem(tab_entry->fd, request->key.data, request->value.data, 0);
            reply.status = TABLE_STATUS__SUCCESS;
        }
    }

    int packet_len = table_entry_insert_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__TABLE_ENTRY_INSERT_REPLY, packet_len);

    table_entry_insert_reply__pack(&reply, packet + HEADER_LENGTH);

    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    free(packet);
    table_entry_insert_request__free_unpacked(request, NULL);

    return len;
}

int recv_table_entry_delete_request(void *buffer, struct header *header)
{
    TableEntryDeleteRequest *request;
    TableEntryDeleteReply reply = TABLE_ENTRY_DELETE_REPLY__INIT;

    request = table_entry_delete_request__unpack(NULL, header->length, buffer);
    int len = table_entry_delete_request__get_packed_size(request);

    reply.status = TABLE_STATUS__STAGE_NOT_FOUND;

    if (request->index <= PIPELINE_STAGES && pipeline[request->index].vm != NULL)
    {
        struct stage *stage = &pipeline[request->index];

        char table_name[32] = {0};
        strncpy(table_name, request->table_name, 31);
        struct table_entry *tab_entry;
        int tables = ubpf_get_tables(stage->vm);
        int ret = bpf_lookup_elem(tables, table_name, &tab_entry);

        if (ret == -1)
        {
            reply.status = TABLE_STATUS__TABLE_NOT_FOUND;
        }
        else
        {
            ret = bpf_delete_elem(tab_entry->fd, request->key.data);
            if (ret == -1)
            {
                reply.status = TABLE_STATUS__ENTRY_NOT_FOUND;
            }
            else
            {
                reply.status = TABLE_STATUS__SUCCESS;
            }
        }
    }

    int packet_len = table_entry_delete_reply__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__TABLE_ENTRY_DELETE_REPLY, packet_len);

    table_entry_delete_reply__pack(&reply, packet + HEADER_LENGTH);

    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    free(packet);
    table_entry_delete_request__free_unpacked(request, NULL);

    return len;
}

int recv_packet_out(void *buffer, struct header *header)
{
    PacketOut *request;
    request = packet_out__unpack(NULL, header->length, buffer);
    int len = packet_out__get_packed_size(request);

    agent.transmit(request->data.data, request->data.len, request->out_port, 1);

    packet_out__free_unpacked(request, NULL);

    return len;
}

const handler handlers[] = {
    [HEADER__TYPE__HELLO] = recv_hello,
    [HEADER__TYPE__FUNCTION_ADD_REQUEST] = recv_function_add,
    [HEADER__TYPE__FUNCTION_REMOVE_REQUEST] = recv_function_remove,
    [HEADER__TYPE__FUNCTION_LIST_REQUEST] = recv_function_list,

    [HEADER__TYPE__TABLES_LIST_REQUEST] = recv_tables_list_request,

    [HEADER__TYPE__TABLE_LIST_REQUEST] = recv_table_list_request,
    [HEADER__TYPE__TABLE_ENTRY_GET_REQUEST] = recv_table_entry_get_request,
    [HEADER__TYPE__TABLE_ENTRY_INSERT_REQUEST] = recv_table_entry_insert_request,
    [HEADER__TYPE__TABLE_ENTRY_DELETE_REQUEST] = recv_table_entry_delete_request,
    [HEADER__TYPE__PACKET_OUT] = recv_packet_out,
};

int agent_packetin(void *pkt, size_t len)
{
    PacketIn reply = PACKET_IN__INIT;
    reply.data.len = len;
    reply.data.data = pkt;

    int packet_len = packet_in__get_packed_size(&reply);
    void *packet = create_packet(HEADER__TYPE__PACKET_IN, packet_len);

    packet_in__pack(&reply, packet + HEADER_LENGTH);

    send(agent.fd, packet, HEADER_LENGTH + packet_len, MSG_NOSIGNAL);

    return 0;
}

uint64_t pipeline_exec(void *pkt, size_t len)
{
    int i;
    uint64_t ret = DROP;

    for (i = 0; i < PIPELINE_STAGES; i++)
    {
        struct stage *stage = &pipeline[i];

        // Skip if this stage is empty
        if (stage->vm != NULL)
        {
#if __x86_64__
            ret = stage->exec(pkt, len);
#else
            ret = ubpf_exec(vm, mem, mem_len);
#endif

            stage->counter++;

            // If it's anything other than NEXT then we made a decision. Stop executing the pipeline
            if ((ret & OPCODE_MASK) != NEXT)
            {
                break;
            }

            // By default we will go to the next stage but we can skip to a further stage if necessary
            i += ret & VALUE_MASK;
        }
    }

    return ret;
}

void *agent_task()
{
    //
    uint8_t buf[8192]; // TODO should have a proper buffer that wraps around and expand if the message is bigger than this
    struct sockaddr_in saddr;

    //
    char *controller_address, *controller_ip, *controller_port;
    controller_address = controller_port = strdup(agent.options->controller);
    controller_ip = strsep(&controller_port, ":");

    //
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(atoi(controller_port));
    if (inet_pton(AF_INET, controller_address, &saddr.sin_addr) <= 0)
    {
        perror("error resolving server address");
        pthread_exit(NULL);
    }

    while (likely(!sigint))
    {
        // Connect to the controller
        agent.fd = socket(AF_INET, SOCK_STREAM, 0);

        if (agent.fd >= 0)
        {
            if (connect(agent.fd, (struct sockaddr *)&saddr, sizeof(saddr)) == 0)
            {
                // CONFIGURATION
                send_hello();

                // MAIN Event Loop
                struct header header;
                while (likely(!sigint))
                {
                    // Recv can get multiple headers + payload
                    int offset = 0;
                    int len = recv(agent.fd, buf, sizeof(buf), 0);
                    // printf("received length %d\n", len);

                    if (len <= 0)
                    {
                        break;
                    }

                    // Not great if we don't receive a full header + payload in one go
                    while (len - offset >= HEADER_LENGTH)
                    {
                        // Read the packet header
                        uint16_t *head = (uint16_t *)(buf + offset);
                        header.type = ntohs(head[0]);
                        header.length = ntohs(head[1]);
                        offset += HEADER_LENGTH;

                        // printf("received packet type: %d length %d\n", header.type, header.length);

                        handler h = handlers[header.type];
                        offset += h(buf + offset, &header);
                    }
                }

                // TEARDOWN
                close(agent.fd);
            }
        }

        perror("unable to connect to the controller");
        sleep(5);
    }

    pthread_exit(NULL);
}

int agent_start(tx_packet_fn tx_fn, struct agent_options *opts)
{
    int err;
    pthread_t agent_thread;

    agent.transmit = tx_fn;
    agent.options = opts;

    err = pthread_create(&agent_thread, NULL, agent_task, NULL);
    return err;
}

int agent_stop(void)
{
    sigint = 1;
    return sigint;
}
