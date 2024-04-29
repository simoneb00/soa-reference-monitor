#!/bin/bash

echo "creating testing directories/subdirectories/files (if not existing)"
if [ ! -d "test" ]; then 
    mkdir test 
fi 
if [ ! -f "test/test.txt" ]; then 
    touch test/test.txt 
fi 
if [ ! -d "test/test1" ]; then 
    mkdir test/test1
fi
if [ ! -f "test/test1/test.txt" ]; then
    touch test/test1/test.txt
fi

if [ ! -f "test.txt" ]; then
    touch test.txt
fi
echo ""

# switch state to REC ON (a password should be requested)
echo "State switch to REC-ON"
sudo switch_state 3
echo ""

# add directories and files to blacklist
echo "Adding test/ and test.txt to the blacklist"
add_to_blacklist test
add_to_blacklist test.txt
echo ""

print_blacklist
echo ""