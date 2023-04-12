/*
 *
 *    Copyright 2023 Jay Logue
 *    All rights reserved.
 * 
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *          Interface for Tiny Echo Server -- An minimal IPv4 stack and
 *          echo server implemented in a single C function.
 */

#ifndef __TINYECHOSERVER_H__
#define __TINYECHOSERVER_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint8_t TinyEchoServer_IPAddress[4];
extern uint8_t TinyEchoServer_MACAddress[6];

extern bool TinyEchoServer_ProcessEthernetFrame(uint8_t * frameBuf, uint32_t * frameLen);

#ifdef __cplusplus
}
#endif

#endif /* __TINYECHOSERVER_H__ */