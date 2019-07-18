#!/bin/bash

export CUBE_PATH=/root/centoscloud/cube-1.3
export CUBE_TCM_PATH=`pwd`
export LD_LIBRARY_PATH=$CUBE_PATH/cubelib/lib/:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=`pwd`/locallib/bin:$LD_LIBRARY_PATH
$CUBE_PATH/proc/main/envset_proc $1 $2 $3 
