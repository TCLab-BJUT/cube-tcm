#!/bin/bash

export LD_LIBRARY_PATH=`pwd`/locallib/bin:$LD_LIBRARY_PATH
$CUBE_PATH/proc/main/envset_proc $1 $2 $3 
