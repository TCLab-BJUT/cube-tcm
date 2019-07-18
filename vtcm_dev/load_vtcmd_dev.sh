#!/bin/sh
insmod ./vtcmd_dev.ko 
chmod 666 /dev/tcm
chmod 666 /dev/vtcm*
