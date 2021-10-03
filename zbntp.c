/*
 * Zabbix loadable module for monitoring of NTP services via native
 * requests and responses analyze.
 */


#include "sysinc.h"
#include "module.h"
#include "log.h"

#define MODULE_NAME "zbntp.so"
#define CACHE_UPDATE 60 /* repeat ntp request only after ... sec */


/* timeout for item processing */
static struct timeval item_timeout;


/* exported metrics */
static int zbntp_get_online(AGENT_REQUEST *request, AGENT_RESULT *result);
static int zbntp_get_stratum(AGENT_REQUEST *request, AGENT_RESULT *result);

static ZBX_METRIC keys[] = {
    {"zbntp.online",  CF_HAVEPARAMS, zbntp_get_online,  "127.0.0.1,123"},
    {"zbntp.stratum", CF_HAVEPARAMS, zbntp_get_stratum, "127.0.0.1,123"},
    {NULL}
};


/* NTP packet structure */
typedef struct {
    uint8_t li_ver_mode;
    uint8_t stratum;
    uint8_t poll_int;
    int8_t precision;
    /* next fields must be divided by 65536 */
    uint32_t root_delay;
    uint32_t root_dispersion;
    /* refid representation depends on stratum. read wiki :) */
    uint32_t refid;
    /* next fields must be divided by 2^32 */
    uint64_t reference_ts;
    uint64_t origin_ts;
    uint64_t receive_ts;
    uint64_t transmit_ts;
} ntp_data;


/* cache as linked list */
typedef struct PacketCache PacketCache;
struct PacketCache {
    struct sockaddr_in server_addr;
    time_t request_time;
    ntp_data response;
    PacketCache* next;
};
static PacketCache* zbntp_cache = NULL;


/* packet to send. constants were taken from 'ntpdate -q' dump with
 * some variation */
const ntp_data empty_request = {0xe3, 0, 10, 0xfa, 0x10000, 0x10000, 0, 0, 0, 0};


/* some common functions */
int	zbx_module_api_version(void)
{
	return ZBX_MODULE_API_VERSION;
}

void zbx_module_item_timeout(int timeout)
{
    zabbix_log(LOG_LEVEL_INFORMATION,
               "%s: setting item timeout = %d",
               MODULE_NAME, timeout);
    item_timeout.tv_sec = timeout;
    item_timeout.tv_usec = 0;
}

int zbx_module_init(void)
{
    zabbix_log(LOG_LEVEL_INFORMATION,
               "Module: %s - build with agent: %d.%d.%d (%s:%d)",
               MODULE_NAME, ZABBIX_VERSION_MAJOR, ZABBIX_VERSION_MINOR,
               ZABBIX_VERSION_PATCH, __FILE__, __LINE__);

    /* set default timeout */
    item_timeout.tv_sec = 1;
    item_timeout.tv_usec = 0;

    return ZBX_MODULE_OK;
}

int zbx_module_uninit(void)
{
    /* clear cache */
    PacketCache* pc = NULL;
    while (zbntp_cache != NULL) {
        pc = zbntp_cache->next;
        free(zbntp_cache);
        zbntp_cache = pc;
    }
    return ZBX_MODULE_OK;
}

ZBX_METRIC *zbx_module_item_list(void)
{
    return keys;
}


/* network side */
int zbntp_do_request(AGENT_RESULT *result, PacketCache *response)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Can not create socket: %s (%s:%d)",
                   MODULE_NAME, strerror(errno), __FILE__, __LINE__);
        SET_MSG_RESULT(result, strdup("Internal module error"));
        return SYSINFO_RET_FAIL;
    }

    const struct sockaddr_in saddr = response->server_addr;
    if (connect(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr)) < 0) {
        close(sock);
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Can not connect to socket: %s (%s:%d)",
                   MODULE_NAME, strerror(errno), __FILE__, __LINE__);
        SET_MSG_RESULT(result, strdup("Internal module error"));
        return SYSINFO_RET_FAIL;
    }

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&item_timeout, sizeof(item_timeout));
    
    if (write(sock, &empty_request, sizeof(empty_request)) < 0) {
        close(sock);
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Error while sending request: %s (%s:%d)",
                   MODULE_NAME, strerror(errno), __FILE__, __LINE__);
        SET_MSG_RESULT(result, strdup("Error while sending request"));
        return SYSINFO_RET_FAIL;
    }
    
    if(read(sock, &(response->response), sizeof(ntp_data)) < 0) {
        close(sock);
        char* strerr = strerror(errno);
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Error while reading response: %s (%s:%d)",
                   MODULE_NAME, strerr, __FILE__, __LINE__);
        SET_MSG_RESULT(result, strdup(strerr));
        return SYSINFO_RET_FAIL;
    }
    close(sock);
    response->request_time = time(NULL);
    return SYSINFO_RET_OK;
}

/* work with cached responses. common function for all metrics */
int zbntp_get_response(AGENT_REQUEST *request, AGENT_RESULT *result, PacketCache **response)
{
    char *host;
    int port = 123;
    struct sockaddr_in addr;
    time_t now = time(NULL);
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    /* try to get addr:port from request */
    if (1 > request->nparam) {
        SET_MSG_RESULT(result, strdup("Server address required"));
        return SYSINFO_RET_FAIL;
    }
    host = get_rparam(request, 0);
    if (1 < request->nparam) {
        char *param2;
        param2 = get_rparam(request, 1);
        if (param2 != NULL) {
            port = atoi(param2);
        }
    }
    
    /* make addr struc */
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, host, &addr.sin_addr);
    addr.sin_port = htons(port);
    
    /* search addr in cache */
    PacketCache* pc = zbntp_cache;
    PacketCache* last_pc = NULL;
    while (pc != NULL) {
        if (memcmp(&pc->server_addr, &addr, sizeof(struct sockaddr_in)) == 0) { /* found */
            if (pc->request_time + CACHE_UPDATE < now) {
                /* update response */
                *response = pc;
                return zbntp_do_request(result, pc);
            }
            else {
                *response = pc;
                return SYSINFO_RET_OK;
            }
        }
        last_pc = pc;
        pc = pc->next;
    }
    
    /* create new element in cache */
    /* Save the thread! */
    pthread_mutex_lock(&mutex);
    
    pc = (PacketCache *) malloc(sizeof(PacketCache));
    if (pc == NULL) {
        SET_MSG_RESULT(result, strdup("Memory allocation error"));
        /* don't forget to free mutex */
        pthread_mutex_unlock(&mutex);
        return SYSINFO_RET_FAIL;
    }
    pc->next = NULL;
    pc->server_addr = addr;
    pc->request_time = 0;
    
    if (last_pc == NULL) {
        zbntp_cache = pc;
    }
    else {
        last_pc->next = pc;
    }
    
    /* free mutex */
    pthread_mutex_unlock(&mutex);
    
    *response = pc;
    return zbntp_do_request(result, pc);
}

static int zbntp_get_online(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    PacketCache* pc = NULL;
    int is_online = 1;
    
    if (zbntp_get_response(request, result, &pc) != SYSINFO_RET_OK) {
        is_online = 0;
    }
    
    SET_UI64_RESULT(result, is_online);
    return SYSINFO_RET_OK;
}

static int zbntp_get_stratum(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    PacketCache* pc = NULL;
    
    int ret = zbntp_get_response(request, result, &pc);
    if (ret != SYSINFO_RET_OK) {
        return ret;
    }

    /* pofigistic */
    SET_UI64_RESULT(result, pc->response.stratum);
    return SYSINFO_RET_OK;
}
