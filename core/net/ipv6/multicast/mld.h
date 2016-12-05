/**
 * \addtogroup uip6
 * @{
 */

/**
 * \file
 *         MLDv1 multicast registration handling (RFC 2710)
 * \author Phoebe Buckheister	<phoebe.buckheister@itwm.fhg.de>
 * \author James Hart
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

#ifndef MLD_H_
#define MLD_H_

#include "contiki-conf.h"

#if MLD_CONF

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"

//Report timeout for unsolicited reports for multicast adresses, in seconds.
#define UIP_ICMP6_MLD_UNSOLICITED_REPORT_INTERVAL 1

//Send an initial report for this multicast address for new listening.
void mld_initial_report(uip_ds6_maddr_t * addr);

//Send a report for this multicast address
void mld_report(const uip_ip6addr_t * addr);

//Send a 'listener done' message
void mld_done(const uip_ip6addr_t * addr);

//Process an MLD query, and schedule appropriate reports
void mld_query_input(void);

//Process an MLD report, which will stop us sending our own report
void mld_report_input(void);

//Periodically calls MLD reporting function if required
void mld_periodic(void *null);

//Register ICMPv6 handler for MLD packets
void mld_init(void);

extern struct ctimer mld_timer_periodic;

#endif

#endif
