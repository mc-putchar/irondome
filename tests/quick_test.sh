#!/usr/bin/env bash

LOG_FILE=/var/log/irondome/irondome.log
TEST_DIR=/tmp/irondome_test

sudo rm -f $LOG_FILE
sudo pkill irondome

mkdir -p $TEST_DIR
for i in {1..50}; do
    python3 -c 'print("Plaintext data for Iron Dome testing " * 500)' > "$TEST_DIR/file_$i.txt"
done

sudo irondome $TEST_DIR

for i in {1..3}; do cat $TEST_DIR/file_*.txt > /dev/null; done

openssl enc -aes-256-cbc -pbkdf2 -pass pass:secret \
    -in $TEST_DIR/file_1.txt \
    -out $TEST_DIR/file_1.txt.enc

mv $TEST_DIR/file_1.txt.enc $TEST_DIR/file_1.txt

sudo grep "ALERT" $LOG_FILE
