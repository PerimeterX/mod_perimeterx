#!/bin/bash

sed -i 's@APP_ID@'"$APP_ID"'@' /home/r/mod_perimeterx/t/conf/extra.conf.in
sed -i 's@TOKEN@'"$AUTH_TOKEN"'@' /home/r/mod_perimeterx/t/conf/extra.conf.in

./home/r/mod_perimeterx/t/TEST -v
