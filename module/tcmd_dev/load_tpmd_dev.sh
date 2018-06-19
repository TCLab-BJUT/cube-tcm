#!/bin/sh
insmod ./tcmd_dev.ko tcmd_socket_name="127.0.0.1" tcmd_port=$1
