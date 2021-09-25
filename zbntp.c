/*
 * Zabbix loadable module for monitoring of NTP services via native
 * requests and responses analyze.
 */


#include "sysinc.h"
#include "module.h"


/* timeout for item processing */
static int item_timeout = 0;


/* cache as linked list */
typedef struct PacketCache PacketCache;
struct PacketCache {
    int stratum;
    time_t request_time;
    PacketCache* next;
};

static PacketCache* zbntp_cache = NULL;


/* some common functions */
int	zbx_module_api_version(void)
{
	return ZBX_MODULE_API_VERSION;
}

void	zbx_module_item_timeout(int timeout)
{
	item_timeout = timeout;
}
