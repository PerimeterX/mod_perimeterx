#!/bin/bash

adduser --disabled-password --gecos '' r
adduser r sudo
echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
#su -m r -c  bash "/tmp/run-test.sh"

