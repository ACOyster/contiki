/**
 * \addtogroup uip6
 * @{
 */

/**
 * \file
 *         MLDv1 multicast registration handling (RFC 2710)
 * \author Phoebe Buckheister	<phoebe.buckheister@itwm.fhg.de>
 * \author James Hart (adjusted to operate on router nodes)
 */

/*
 * Copyright (c) 2014, Fraunhofer ITWM
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "net/ipv6/multicast/mld.h"
#include "net/ipv6/multicast/uip-mcast6-route.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-icmp6.h"
#include "net/ip/tcpip.h"
#include "lib/random.h"
#include <stdbool.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#if MLD_CONF

#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_ICMP6_ERROR_BUF ((struct uip_icmp6_error *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ICMP6_MLD_BUF ((struct uip_icmp6_mld *)&uip_buf[uip_l2_l3_icmp_hdr_len])

#define UIP_HBHO_LEN 2
#define UIP_RTR_ALERT_LEN 4
#define UIP_PADN_LEN 2

#ifdef UIP_FALLBACK_INTERFACE
extern struct uip_fallback_interface UIP_FALLBACK_INTERFACE;
#endif

struct ctimer mld_timer_periodic;

static inline void mld_set_report_time(uip_ds6_maddr_t * addr, uint16_t timeout)
{
  int when = random_rand() % timeout;

  PRINTF("MLD: Report in %is: ", when);
  PRINT6ADDR(&addr->ipaddr);
  PRINTF("\n");
  stimer_set(&addr->report_timeout, when);
}

static void send_mldv1_packet(uip_ip6addr_t * maddr, uint8_t mld_type)
{
  if(mld_type == ICMP6_MLD_REPORT)
  {
	uip_ipaddr_copy(&UIP_IP_BUF->destipaddr, maddr);	//Reports send to the maddr
  } else {
    uip_create_linklocal_allnodes_mcast(&UIP_IP_BUF->destipaddr);	//Done sends to the allrouters mcast
  }

  UIP_IP_BUF->ttl = 1;

  uip_ipaddr_copy(&UIP_IP_BUF->srcipaddr, &uip_ds6_get_link_local(ADDR_PREFERRED)->ipaddr);

  UIP_IP_BUF->proto = UIP_PROTO_HBHO;
  uip_len = UIP_LLH_LEN + UIP_IPH_LEN;

  //HBHO header, length will alwasy be 1, the number of octets the extension contains
  ((uip_hbho_hdr *) & uip_buf[uip_len])->next = UIP_PROTO_ICMP6;
  ((uip_hbho_hdr *) & uip_buf[uip_len])->len = (UIP_HBHO_LEN + UIP_RTR_ALERT_LEN + UIP_PADN_LEN) / 8 - 1;
  uip_len += UIP_HBHO_LEN;

  //Router Alert
  ((uip_ext_hdr_rtr_alert_tlv *) & uip_buf[uip_len])->tag = UIP_EXT_HDR_OPT_RTR_ALERT;
  ((uip_ext_hdr_rtr_alert_tlv *) & uip_buf[uip_len])->len = 2;
  ((uip_ext_hdr_rtr_alert_tlv *) & uip_buf[uip_len])->value = 0;
  uip_len += UIP_RTR_ALERT_LEN;

  //Pad for HBHO header
  ((uip_ext_hdr_padn_tlv *) & uip_buf[uip_len])->tag = UIP_EXT_HDR_OPT_PADN;
  ((uip_ext_hdr_padn_tlv *) & uip_buf[uip_len])->len = 0;
  uip_len += UIP_PADN_LEN;

  uip_ext_len = UIP_HBHO_LEN + UIP_RTR_ALERT_LEN + UIP_PADN_LEN;

  uip_len += UIP_ICMPH_LEN;

  uip_len += UIP_ICMP6_MLD_LEN;

  UIP_IP_BUF->len[0] = ((uip_len - UIP_IPH_LEN) >> 8);
  UIP_IP_BUF->len[1] = ((uip_len - UIP_IPH_LEN) & 0xff);
  UIP_ICMP_BUF->type = mld_type;
  UIP_ICMP_BUF->icode = 0;

  UIP_ICMP6_MLD_BUF->maximum_delay = 10;
  UIP_ICMP6_MLD_BUF->reserved = 0;
  uip_ipaddr_copy(&UIP_ICMP6_MLD_BUF->address, maddr);

  UIP_ICMP_BUF->icmpchksum = 0;
  UIP_ICMP_BUF->icmpchksum = ~uip_icmp6chksum();

  UIP_FALLBACK_INTERFACE.output();
  uip_clear_buf();
  UIP_STAT(++uip_stat.icmp.sent);
}

void mld_initial_report(uip_ds6_maddr_t * addr)
{
  if (uip_is_addr_mcast_global(&addr->ipaddr))
  {
	mld_report(&addr->ipaddr);
	stimer_set(&addr->report_timeout, UIP_ICMP6_MLD_UNSOLICITED_REPORT_INTERVAL);
	ctimer_set(&mld_timer_periodic, CLOCK_SECOND / 4, &mld_periodic, NULL);
  }
  else
  {
	PRINTF("MLD: No report scheduled for non-global MC address ");
	PRINT6ADDR(addr);
	PRINTF("\n");
  }
}

void mld_report(const uip_ip6addr_t * addr)
{
  PRINTF("MLD: Sending MLDv1 report for ");
  PRINT6ADDR(addr);
  PRINTF("\n");

  send_mldv1_packet(addr, ICMP6_MLD_REPORT);
}

void mld_done(const uip_ip6addr_t * addr)
{
  send_mldv1_packet(addr, ICMP6_MLD_DONE);
  
  PRINTF("MLD: Sending MLDv1 done for ");
  PRINT6ADDR(addr);
  PRINTF("\n");
}

void mld_query_input(void)
{
  uip_ds6_maddr_t *addr;
  uint8_t m;
  uint16_t max_delay;

  PRINTF("MLD: Received MLD query from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" for ");
  PRINT6ADDR(&UIP_ICMP6_MLD_BUF->address);
  PRINTF("\n");

  max_delay = uip_ntohs(UIP_ICMP6_MLD_BUF->maximum_delay);

  if (!uip_is_addr_linklocal_allnodes_mcast(&UIP_ICMP6_MLD_BUF->address)
     && uip_ds6_is_my_maddr(&UIP_ICMP6_MLD_BUF->address))
  //Multicast Address Specific Query, for a MC address we are listening to
  {
    addr = uip_ds6_maddr_lookup(&UIP_ICMP6_MLD_BUF->address);
    addr->report_count = 1;	//Set report count to 1
    mld_set_report_time(addr, max_delay / 1000);	//Set report time
  }
  else if (uip_is_addr_unspecified(&UIP_ICMP6_MLD_BUF->address))
  //General Query, send report to all MC addresses we are listening to
  {
    for (m = 0; m < UIP_DS6_MADDR_NB; m++)
    {
      if (uip_ds6_if.maddr_list[m].isused && uip_is_addr_mcast_global(&uip_ds6_if.maddr_list[m].ipaddr))
      {
    	uip_ds6_if.maddr_list[m].report_count = 1;	//Set report count to 1
	    mld_set_report_time(&uip_ds6_if.maddr_list[m], max_delay / 1000);	//Set report time
	  }
    }
  }
  ctimer_set(&mld_timer_periodic, CLOCK_SECOND / 4, &mld_periodic, NULL);

  uip_len = 0;
}

void mld_report_input(void)
{
  uip_ds6_maddr_t *addr;

  PRINTF("MLD: Received MLD report from ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF(" for ");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("\n");

  if (uip_ext_len == 0) {
    PRINTF("MLD: MLD packet without hop-by-hop header received\n");
  } else if (uip_ds6_is_my_maddr(&UIP_ICMP6_MLD_BUF->address)) 	//If we are listening to MC address
  {
    addr = uip_ds6_maddr_lookup(&UIP_ICMP6_MLD_BUF->address);
    if (addr->report_count > 0)
      addr->report_count--;	//Reduce the report count by 1
  }

  uip_len = 0;
}

void mld_periodic(void *null)
{
  uint8_t m;
  uip_ds6_maddr_t *addr;
  bool furtherReports = false;

  for (m = 0; m < UIP_DS6_MADDR_NB; m++) {	//All reports triggered each time this is called
    addr = &uip_ds6_if.maddr_list[m];
    if (addr->isused && addr->report_count) {
      if (stimer_expired(&addr->report_timeout)) {
        mld_report(&addr->ipaddr);
        if (--addr->report_count) {
          if (addr->report_timeout.interval == 0) {
            mld_set_report_time(addr, UIP_ICMP6_MLD_UNSOLICITED_REPORT_INTERVAL); }
          stimer_restart(&addr->report_timeout);
        }
      }
      furtherReports = true;
    }
  }

  if (furtherReports)
	  ctimer_reset(&mld_timer_periodic);
}

void mld_init(void)
{
	PRINTF("MLD: Registering for ICMP6 handles\n");
	UIP_ICMP6_HANDLER(mld_query_handler, ICMP6_MLD_QUERY, 0x00, mld_query_input);
	UIP_ICMP6_HANDLER(mld_report_handler, ICMP6_MLD_REPORT, 0x00, mld_report_input);

	uip_icmp6_register_input_handler(&mld_query_handler);
	uip_icmp6_register_input_handler(&mld_report_handler);
}

#endif /*MLD_CONF*/
