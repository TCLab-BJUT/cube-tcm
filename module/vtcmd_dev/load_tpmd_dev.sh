#!/bin/sh
insmod ./vtcmd_dev.ko vtcmd_socket_name="127.0.0.1" vtcmd_port=$1
