#!/bin/sh
insmod ./tpmd_dev.ko tpmd_socket_name="127.0.0.1" tpmd_port=$1
