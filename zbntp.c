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
}

