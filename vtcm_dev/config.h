/* Software-based Trusted Platform Module (TCM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *
 * This module is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id: config.h.in 426 2010-02-22 17:11:58Z mast $
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

/* project and build version */
#define VERSION_MAJOR 0
#define VERSION_MINOR 7
#define VERSION_BUILD 461

/* TDDL and LKM configuration */
#define VTCM_DEVICE_NAME  "/dev/vtcm"
#define VTCM_CMD_BUF_SIZE 4096
#define VTCM_DEFAULT_NUM  16
#define DIGEST_SIZE       32
#define BYTE              unsigned char
#define VTCM_CHANNEL_BUF_SIZE 8192

#endif /* _CONFIG_H_ */

