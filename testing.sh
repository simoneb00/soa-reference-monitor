#!/bin/bash

error_counter=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script with sudo privileges${NC}"
    exit 1
fi


# creating testing directories/subdirectories/files (if not existing)
if [ ! -d "test" ]; then
    mkdir test
    touch test/test.txt
    mkdir test/test1
    touch test/test1/test.txt
fi

if [ ! -f "test.txt" ]; then
    touch test.txt
fi

# switch state to REC ON (a password should be requested)
switch_state 3

# add directories and files to blacklist
add_to_blacklist test
add_to_blacklist test.txt

# try to write on blacklisted file
echo "test" > test.txt
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted file update was successful"
    ((error_counter++))
fi

# try to remove blacklisted directory test
rm -r test
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted directory has been removed"
    ((error_counter++))
fi

# try to remove blacklisted file
rm -r test.txt
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted file has been removed"
    ((error_counter++))
fi

# try to create a subdirectory inside a blacklisted directory 
mkdir test/test2
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} subdir creation inside blacklisted dir was successful"
    ((error_counter++))
fi

# try to create a file inside a blacklisted directory
touch test/test2.txt
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} file creation inside blacklisted dir was successful"
    ((error_counter++))
fi

# try to create an hard link to a blacklisted file
ln test.txt hl_test
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} hard link creation to a blacklisted file was successful"
    ((error_counter++))
fi

ln test/test1/test.txt hl_test1
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} hard link creation to a blacklisted file was successful"
    ((error_counter++))
fi

# try to create a symlink to a blacklisted directory
ln -s test sym_test
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} symlink creation to a blacklisted dir was successful"
    ((error_counter++))
fi

# try to create a symlink to a blacklisted file
ln -s test/test.txt sym_test_file
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} symlink creation to a blacklisted file was successful"
    ((error_counter++))
fi

echo ""
if [ ${error_counter} == 0 ]; then
    echo -e "${GREEN}Tests completed with ${error_counter} errors${NC}"
else
    echo -e "${RED}Tests completed with ${error_counter} errors${NC}"
fi
echo ""

# remove blacklisted directory (DELETE_DIRS_ONLY)
echo "Removing test/ from blacklist (DELETE_DIRS_ONLY: only dirs/subdirs should be removed)"
remove_from_blacklist test 0
echo ""
print_blacklist
echo ""

# remove blacklisted directory (DELETE_ALL)
echo "Removing test/ from blacklist (DELETE_ALL: test/ dir and all its content should be removed)"
remove_from_blacklist test 1
echo ""
print_blacklist
echo ""

echo "Removing test.txt from blacklist"
remove_from_blacklist test.txt 1
echo ""
print_blacklist
echo ""





