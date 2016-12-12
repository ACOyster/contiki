#ifndef MLD_H_
#define MLD_H_

#include "contiki-conf.h"

#if UIP_CONF_MLD

#include <stdbool.h>

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-icmp6.h"
#include "lib/random.h"

#define DEBUG DEBUG_NONE
#if DEBUG
#include "net/ip/uip-debug.h"
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

//Report timeout for multicast adresses, in seconds.
#define UIP_IP6_MLD_REPORT_INTERVAL 10

/*//Send an initial report for this multicast address for new listening.
void uip_icmp6_mldv1_initial_report(uip_ds6_maddr_t * addr);

//Send a report for this multicast address
void uip_icmp6_mldv1_report(uip_ip6addr_t * addr);

//Send a 'listener done' message
void uip_icmp6_mldv1_done(uip_ip6addr_t * addr);

//Process an MLD query, and schedule appropriate reports
void uip_icmp6_ml_query_input(void);

//Process an MLD report, which will stop us sending our own report
void uip_icmp6_ml_report_input(void);

//Periodically calls MLD reporting function if required
void uip_mld_periodic(void);*/

void icmptest(uip_ip6addr_t * addr);

extern struct etimer uip_mld_timer_periodic;

#endif

#endif
