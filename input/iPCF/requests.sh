#!/bin/sh

while true
do
    dig www.google.de
    curl http://www.google.de
    dig splone.com
    curl https://splone.com
    sleep 1
done

