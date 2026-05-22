/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "certificate_test.h"
#include "aern_utils.h"
#include "adc_test.h"
#include "aps_test.h"
#include "client_test.h"
#include "e2e_test.h"
#include "ars_test.h"
#include "network_test.h"
#include "replay_test.h"
#include "route_test.h"
#include "topology_test.h"
#include "virtual_test.h"

static void print_empty_line()
{
	aerntest_print_line("");
}

static void print_title(void)
{
	aerntest_print_line("***************************************************");
	aerntest_print_line("* AERN: Anonymous Encrypted Relay Netwok          *");
	aerntest_print_line("*                                                 *");
	aerntest_print_line("* Release:   v1.0.0.0a (A1)                       *");
	aerntest_print_line("* License:   QRCS-PL                              *");
	aerntest_print_line("* Date:      May 17, 2026                         *");
	aerntest_print_line("* Contact:   contact@qrcscorp.ca                  *");
	aerntest_print_line("***************************************************");
	print_empty_line();
}

int main(void)
{
	print_title();

	aerntest_print_line("Certificate encoding, validation, and negative paths.");
	 
	if (aerntest_certificate_run() == true)
	{
		aerntest_print_line("Success! AERN certificate tests.");
	}
	else
	{
		aerntest_print_line("Failure! certificate tests.");
	}

	print_empty_line();
	aerntest_print_line("Root server initialization and readiness checks.");

	if (aerntest_ars_run() == true)
	{
		aerntest_print_line("Success! AERN ARS tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN ARS tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Domain-controller initialization and readiness checks.");

	if (aerntest_adc_run() == true)
	{
		aerntest_print_line("Success! AERN ADC tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN ADC tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Proxy initialization, topology coherence, and mesh-readiness checks.");

	if (aerntest_aps_run() == true)
	{
		aerntest_print_line("Success! AERN APS tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN APS tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Client initialization, topology join state, and entry tunnel readiness.");

	if (aerntest_client_run() == true)
	{
		aerntest_print_line("Success! AERN client tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN client tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("End-to-end relay, session, and return paths.");

	if (aerntest_e2e_run() == true)
	{
		aerntest_print_line("Success! AERN end-to-end substrate tests.");
	}
	else
	{
		aerntest_print_line("Failure! AERN end-to-end substrate tests.");
	}

	print_empty_line();
	aerntest_print_line("Network control messages and malformed packets.");

	if (aerntest_network_run() == true)
	{
		aerntest_print_line("Success! AERN network tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN network tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Replay windows, sequencing, and packet timing.");

	if (aerntest_replay_run() == true)
	{
		aerntest_print_line("Success! AERN replay tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN replay tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Route maps, sessions, fragmentation, and queues.");

	if (aerntest_route_run() == true)
	{
		aerntest_print_line("Success! AERN route tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN route tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Topology serialization, lookup, sorting, and enforcement.");

	if (aerntest_topology_run() == true)
	{
		aerntest_print_line("Success! AERN topology tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN topology tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Deterministic virtual fabric and in-memory transport scheduler.");

	if (aerntest_virtual_run() == true)
	{
		aerntest_print_line("Success! AERN virtual fabric tests have passed.");
	}
	else
	{
		aerntest_print_line("Failure! AERN virtual fabric tests have failed.");
	}

	print_empty_line();
	aerntest_print_line("Completed! Press any key to close..");
	aerntest_get_wait();

	return 0;
}
