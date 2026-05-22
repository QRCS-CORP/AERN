/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 */

#ifndef AERN_VIRTUAL_TEST_H
#define AERN_VIRTUAL_TEST_H

#include "aerncommon.h"

/**
 * \file virtual_test.h
 * \brief Deterministic in-process virtual fabric tests for AERNTest.
 */

/**
 * \brief Run the deterministic virtual fabric and virtual transport tests.
 *
 * \return Returns true if all virtual-fabric tests pass.
 */
bool aerntest_virtual_run(void);

#endif
