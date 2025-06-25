/**
 * MIT License
 *
 * Copyright (c) 2025 Serkan Aksoy
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __THREAD_H__
#define __THREAD_H__

#include "manager.h"

#define NHOOK_MAX_IGNORED_ID_COUNT 2

nerror_t transfer_threads(nhook_manager_t *nhook_manager, nhook_t *nhook);

/**
 * @brief Resets thread management data in hook manager
 * @param nhook_manager Hook manager instance
 * @param free_addresses If true, frees allocated memory for thread IDs and handles
 */
void reset_threads(nhook_manager_t *nhook_manager, bool free_addresses);

/**
 * @brief Resumes all suspended threads in the hooked process
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 */
nerror_t resume_threads(nhook_manager_t *nhook_manager);

/**
 * @brief Suspends all threads in the hooked process
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 */
nerror_t suspend_threads(nhook_manager_t *nhook_manager);

/**
 * @brief Updates thread list in hook manager
 * @param nhook_manager Hook manager instance
 * @return nerror_t error code
 * 
 * Refreshes the list of threads in the target process,
 * updating thread IDs and handles. Also removes invalid
 * threads and adds newly created ones.
 */
nerror_t update_threads(nhook_manager_t *nhook_manager);

#endif // !__THREAD_H__
