#!/bin/bash

MAJOR=`git tag | head -1 | awk '{split($0,a,"."); print a[1]}'`
MINOR=`git tag | head -1 | awk '{split($0,a,"."); print a[2]}'`
MICRO=`git rev-list HEAD --count`
TAG=`git log | head -1 | awk '{printf("%s", substr($2, 0, 7))}'`

if [ "$MAJOR" == "" ]; then
	MAJOR=0
	MINOR=0
fi

echo $MAJOR.$MINOR.$MICRO-$TAG
