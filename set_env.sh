#!/bin/bash

if [ $CUBESYSPATH == "" ]
then
    echo "can't find CUBESYSPATH"
    exit
fi

export CUBEAPPPATH=`pwd` 
export CUBE_APP_PLUGIN=$CUBEAPPPATH/plugin/
export LD_LIBRARY_PATH=$CUBEAPPPATH/locallib/bin:$LD_LIBRARY_PATH
