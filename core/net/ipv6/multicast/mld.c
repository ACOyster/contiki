#include "net/ipv6/multicast/mld.h"

#if UIP_CONF_MLD

#define UIP_IP_BUF ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_ICMP_BUF ((struct uip_icmp_hdr *)&uip_buf[uip_l2_l3_hdr_len])
#define UIP_ICMP6_ERROR_BUF ((struct uip_icmp6_error *)&uip_buf[uip_l2_l3_icmp_hdr_len])
#define UIP_ICMP6_MLD_BUF ((struct uip_icmp6_mld1 *)&uip_buf[uip_l2_l3_icmp_hdr_len])

struct etimer uip_mld_timer_periodic;

/*static inline void mld_set_report_time(uip_ds6_maddr_t * addr, uint16_t timeout)
{
  int when = random_rand() % timeout;

  PRINTF("Report in %is:", when);
  PRINT6ADDR(&addr->ipaddr);
  PRINTF("\n");
  stimer_set(&addr->report_timeout, when); //This needs to check if the timer is already lower than this value
}*/

/*static void send_mldv1_packet(uip_ip6addr_t * maddr, uint8_t mld_type)
{
  uip_ipaddr_t destipaddr;*/ //TODO: Remove
  
  /* MLD requires hoplimits to be 1 and source addresses to be link-local.
   * Since routers must send queries from link-local addresses, a link local
   * source be selected.
   * The destination IP must be the multicast group, though, and source address selection
   * will choose a routable address (if available) for multicast groups that are themselves
   * routable. Thus, select the source address before filling the destination.
   **/
  /*UIP_IP_BUF->ttl = 1;
  uip_ds6_select_src(&UIP_IP_BUF->srcipaddr, &UIP_IP_BUF->destipaddr);*/ //TODO: Remove
  /* If the selected source is ::, the MLD packet would be invalid. */
  /*if(uip_is_addr_unspecified(&UIP_IP_BUF->destipaddr)) {
    return;
  }

  if(mld_type == ICMP6_ML_REPORT)
  {
    destipaddr = maddr;
  } else {
    uip_create_linklocal_allrouters_mcast(destipaddr);
  }

  UIP_IP_BUF->proto = UIP_PROTO_HBHO;

  ((uip_hbho_hdr *) & uip_buf[uip_len])->next = UIP_PROTO_ICMP6;*/ //TODO: Remove
  /* we need only pad with two bytes, so the PadN header is sufficient */
  /* also, len is in units of eight octets, excluding the first. */
  /*((uip_hbho_hdr *) & uip_buf[uip_len])->len =
    (UIP_HBHO_LEN + UIP_RTR_ALERT_LEN + UIP_PADN_LEN) / 8 - 1;

  ((uip_ext_hdr_rtr_alert_tlv *) & uip_buf[uip_len])->tag =
    UIP_EXT_HDR_OPT_RTR_ALERT;
  ((uip_ext_hdr_rtr_alert_tlv *) & uip_buf[uip_len])->len = 2;*/ //TODO: Remove  /* data length of value field */
  /*((uip_ext_hdr_rtr_alert_tlv *) & uip_buf[uip_len])->value = 0; */ //TODO: Remove       /* MLD message */

  /*((uip_ext_hdr_padn_tlv *) & uip_buf[uip_len])->tag = UIP_EXT_HDR_OPT_PADN;
  ((uip_ext_hdr_padn_tlv *) & uip_buf[uip_len])->len = 0;*/ //TODO: Remove       /* no data bytes following */

  /*uip_ext_len = UIP_HBHO_LEN + UIP_RTR_ALERT_LEN + UIP_PADN_LEN;
  
  UIP_ICMP6_MLD_BUF->maximum_delay = 0;
  UIP_ICMP6_MLD_BUF->reserved = 0;
  uip_ipaddr_copy(&UIP_ICMP6_MLD_BUF->address, maddr);
  
  uip_icmp6_send(destipaddr, mld_type, 0, UIP_ICMP6_MLD1_LEN)
}*/ //TODO: Remove

/*void uip_icmp6_mldv1_initial_report(uip_ds6_maddr_t * addr)
{
  addr->report_count = 3;
  stimer_set(&addr->report_timeout, 0);		//Should be for config [Unsolicted report interval]
  etimer_set(&uip_mld_timer_periodic, CLOCK_SECOND / 4);
}

void uip_icmp6_mldv1_report(uip_ip6addr_t * addr)
{
  if (uip_is_addr_linklocal_allnodes_mcast(addr)) {
    PRINTF("Not sending MLDv1 report for FF02::1\n");
    return;
  }

  PRINTF("Sending MLDv1 report for");
  PRINT6ADDR(addr);
  PRINTF("\n");

  send_mldv1_packet(addr, ICMP6_ML_REPORT);
}

void uip_icmp6_mldv1_done(uip_ip6addr_t * addr)
{
  if (uip_is_addr_linklocal_allnodes_mcast(addr)) {
    PRINTF("Not sending MLDv1 done for FF02::1\n");
    return;
  }
  send_mldv1_packet(addr, ICMP6_ML_DONE);
  
  PRINTF("Sending MLDv1 done for");
  PRINT6ADDR(addr);
  PRINTF("\n");
}

void uip_icmp6_ml_query_input(void)
{
  uip_ds6_maddr_t *addr;
  uint8_t m;
  uint16_t max_delay;

  PRINTF("Received MLD query from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("for");
  PRINT6ADDR(&UIP_ICMP6_MLD_BUF->address);
  PRINTF("\n");

  max_delay = uip_ntohs(UIP_ICMP6_MLD_BUF->maximum_delay);

  if (uip_ext_len == 0) {
    PRINTF("MLD packet without hop-by-hop header received\n");
    return;
  } else {
    if (!uip_is_addr_linklocal_allnodes_mcast(&UIP_ICMP6_MLD_BUF->address)
       && uip_ds6_is_my_maddr(&UIP_ICMP6_MLD_BUF->address))
    	//Multicast Address Specific Query, for a MC address we are listening to
    {
      addr = uip_ds6_maddr_lookup(&UIP_ICMP6_MLD_BUF->address);
      addr->report_count = 1;	//Set report flag
      mld_set_report_time(addr, max_delay / 1000);	//Set report time
    }
    else if (uip_is_addr_unspecified(&UIP_ICMP6_MLD_BUF->address))
    	//General Query, send report to all MC addresses we are listening to
    {
      for (m = 0; m < UIP_DS6_MADDR_NB; m++)
      {
        if (uip_ds6_if.maddr_list[m].isused)
        {
          uip_ds6_if.maddr_list[m].report_count = 1;	//Set report flag
          mld_set_report_time(&uip_ds6_if.maddr_list[m], max_delay / 1000);	//Set report time
        }
      }
    }
  }
  etimer_set(&uip_mld_timer_periodic, CLOCK_SECOND / 4);	//What does this line do?
}

void uip_icmp6_ml_report_input(void)
{
  uip_ds6_maddr_t *addr;

  PRINTF("Received MLD report from");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  PRINTF("for");
  PRINT6ADDR(&UIP_IP_BUF->destipaddr);
  PRINTF("\n");

  if (uip_ext_len == 0) {
    PRINTF("MLD packet without hop-by-hop header received\n");
  } else if (uip_ds6_is_my_maddr(&UIP_ICMP6_MLD_BUF->address)) 	//If we are listening to MC address
  {
    addr = uip_ds6_maddr_lookup(&UIP_ICMP6_MLD_BUF->address);
    if (addr->report_count > 0)
      addr->report_count--;	//Unset report flag
  }
}

void uip_mld_periodic(void)
{
  uint8_t m;
  uip_ds6_maddr_t *addr;
  bool more = false;

  for (m = 0; m < UIP_DS6_MADDR_NB; m++) {
    addr = &uip_ds6_if.maddr_list[m];
    if (addr->isused && addr->report_count) {
      if (stimer_expired(&addr->report_timeout)) {
        uip_icmp6_mldv1_report(&addr->ipaddr);
        if (--addr->report_count) {
          if (addr->report_timeout.interval == 0) {
            mld_set_report_time(addr, UIP_IP6_MLD_REPORT_INTERVAL); }
          stimer_restart(&addr->report_timeout);
        }
      }
      more = true;
    }
  }

  if (more)
    etimer_set(&uip_mld_timer_periodic, CLOCK_SECOND / 4);
}*/

void icmptest(uip_ip6addr_t * addr)
{
	uip_icmp6_send(addr, 128, 0, 20);
}

#endif
