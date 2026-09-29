/**
 * @file ike_request_format.h
 * @brief IKE request formatting
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2022-2026 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneIPSEC Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.6.6
 **/

#ifndef _IKE_REQUEST_FORMAT_H
#define _IKE_REQUEST_FORMAT_H

//Dependencies
#include "ike/ike.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//IKE related functions
error_t ikeSendRequest(IkeSaEntry *sa);

error_t ikeSendIkeSaInitRequest(IkeSaEntry *sa);
error_t ikeSendIkeAuthRequest(IkeSaEntry *sa);
error_t ikeSendCreateChildSaRequest(IkeSaEntry *sa);
error_t ikeSendInfoRequest(IkeSaEntry *sa);
error_t ikeSendNatKeepalive(IkeSaEntry *sa);

error_t ikeFormatIkeSaInitRequest(IkeSaEntry *sa, uint8_t *p, size_t *length);
error_t ikeFormatIkeAuthRequest(IkeSaEntry *sa, uint8_t *p, size_t *length);

error_t ikeFormatCreateChildSaRequest(IkeSaEntry *sa, uint8_t *p,
   size_t *length);

error_t ikeFormatInfoRequest(IkeSaEntry *sa, uint8_t *p,
   size_t *length);

error_t ikeFormatChildSaCreateRequest(IkeSaEntry *sa, uint8_t *p,
   size_t *length, uint8_t **nextPayload);

error_t ikeFormatIkeSaRekeyRequest(IkeSaEntry *sa, uint8_t *p, size_t *length,
   uint8_t **nextPayload);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
