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
static int item_timeout = 1;


static int zbntp_get_stratum(AGENT_REQUEST *request, AGENT_RESULT *result);

static ZBX_METRIC keys[] = {
    {"zbxntp.stratum", CF_HAVEPARAMS, zbntp_get_stratum, "127.0.0.1,123"},
    {NULL}
};


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
	item_timeout = timeout;
}

int zbx_module_init(void)
{
    zabbix_log(LOG_LEVEL_INFORMATION,
               "Module: %s - build with agent: %d.%d.%d (%s:%d)",
               MODULE_NAME, ZABBIX_VERSION_MAJOR, ZABBIX_VERSION_MINOR,
               ZABBIX_VERSION_PATCH, __FILE__, __LINE__);
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


int zbntp_do_request(AGENT_RESULT *result, PacketCache *response)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Can not create socket (%s:%d)",
                   MODULE_NAME, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    const struct sockaddr_in saddr = response->server_addr;
    if (connect(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) < 0) {
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Can not connect to socket (%s:%d)",
                   MODULE_NAME, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    int ret = write(sock, &empty_request, sizeof(empty_request));
    if (ret < 0) {
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Error while sending request (%s:%d)",
                   MODULE_NAME, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    
    struct timeval timeout;
    timeout.tv_sec = item_timeout;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    
    if(read(sock, &(response->response), sizeof(ntp_data)) < 0) {
        zabbix_log(LOG_LEVEL_ERR,
                   "%s: Error while reading response (%s:%d)",
                   MODULE_NAME, __FILE__, __LINE__);
        return SYSINFO_RET_FAIL;
    }
    response->request_time = time(NULL);
    return SYSINFO_RET_OK;
}

int zbntp_get_response(AGENT_REQUEST *request, AGENT_RESULT *result, PacketCache **response)
{
    char *host;
    int port = 123;
    struct sockaddr_in addr;
    time_t now = time(NULL);
    
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
    pc = (PacketCache *) malloc(sizeof(PacketCache));
    if (pc == NULL) {
        SET_MSG_RESULT(result, strdup("Can not allocate memory!"));
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
    
    return zbntp_do_request(result, pc);
}

static int zbntp_get_stratum(AGENT_REQUEST *request, AGENT_RESULT *result)
{
    PacketCache* pc = NULL;
    int ret = zbntp_get_response(request, result, &pc);
    if (ret != SYSINFO_RET_OK) {
        return ret;
    }
    SET_UI64_RESULT(result, pc->response.stratum);
    return SYSINFO_RET_OK;
}