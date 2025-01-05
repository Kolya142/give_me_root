#!/bin/bash
gcc gmr.c -o /usr/bin/gmr -lcrypt
sudo chown root:root gmr
sudo chmod u+s gmr
echo testing
gmr /bin/id