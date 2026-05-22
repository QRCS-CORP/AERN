#ifndef AERN_CLIENT_TEST_H
#define AERN_CLIENT_TEST_H

#include "aerncommon.h"

/**
 * \file client_test.h
 * \brief AERN client validation tests.
 *
 * \details
 * This header declares the test-group entry point for the AERN client tests. 
 * The declarations are test-harness entry points and are not part of the AERN production API.
 */

 /**
  * \brief Run the AERN client validation test group.
  *
  * \return Returns true when every certificate test succeeds.
  */
bool aerntest_client_run(void);

#endif
