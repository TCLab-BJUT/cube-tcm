#!/bin/bash

if [ $CUBESYSPATH == "" ]
then
    echo "can't find CUBESYSPATH"
    exit
fi

export CUBEAPPPATH=`pwd` 
export CUBE_APP_PLUGIN=$CUBEAPPPATH/plugin/:$CUBE_APP_PLUGIN
export LD_LIBRARY_PATH=$CUBEAPPPATH/locallib/bin:$LD_LIBRARY_PATH
export CUBE_DEFINE_PATH=$CUBEAPPPATH/define:$CUBE_DEFINE_PATH
