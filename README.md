# zbntp_lm - Zabbix NTP Loadable Module

Zabbix loadable module for monitoring NTP servers by sending a simple request and analyzing its response.

Now this module is under initial development and supports next metrics:

- zbntp.online - values 0: offline, 1: online, 2: unknown (not supported yet)
- zbntp.stratum

## Purpose

### Why don't parse "ntpdate -q" output, for example

Because every request cause a fork(). It is just unworthy behavior.

### Why don't realize chronyc or ntpq, for example

Because it is very difficulty and not universally.

### Why don't use "NNTP Service" template

Because it is too poor and gives information only about answer on udp port 123.
NTP-server with stratum-16 will answer too, as if it's all right.

### Why there is answers cache inside

Because each answer contains information for various metrics. Zabbix, on the other hand, requests one metric on one time.
Why, in this case, send a tons of same requests to NTP-server? It is better to analyze recently received answers.

## Building and installation

- First of all, one must have Zabbix sources: https://github.com/zabbix/zabbix
- Go to src/modules and do

      git clone https://github.com/shorrey/zbntp_lm.git
 - make
 - copy zbntp.so to modules directory of your Zabbix server (/usr/lib/zabbix/modules in my case)
 - restart zabbix-server
 - import zbntp_template.xml as template
