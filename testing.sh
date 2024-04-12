#!/bin/bash

error_counter=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run this script with sudo privileges${NC}"
    exit 1
fi


echo "creating testing directories/subdirectories/files (if not existing)"
if [ ! -d "test" ]; then
    mkdir test
    touch test/test.txt
    mkdir test/test1
    touch test/test1/test.txt
fi

if [ ! -f "test.txt" ]; then
    touch test.txt
fi
echo ""

# switch state to REC ON (a password should be requested)
echo "State switch to REC-ON"
switch_state 3
echo ""

# add directories and files to blacklist
echo "Adding test/ and test.txt to the blacklist"
add_to_blacklist test
add_to_blacklist test.txt
echo ""

# try to write on blacklisted file
echo "Attempt to write on blacklisted file test.txt"
echo "test" > test.txt
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted file update was successful"
    ((error_counter++))
fi
echo ""

# try to remove blacklisted directory test
echo "Attempt to remove blacklisted directory test"
rm -r test
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted directory has been removed"
    ((error_counter++))
fi
echo ""

# try to remove blacklisted file
echo "attempt to unlink blacklisted file test.txt"
unlink test.txt
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted file has been removed"
    ((error_counter++))
fi
echo ""

# try to create a subdirectory inside a blacklisted directory 
echo "Attempt to create a subdirectory inside blacklisted dir test/"
mkdir test/test2
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} subdir creation inside blacklisted dir was successful"
    ((error_counter++))
fi
echo ""

# try to create a file inside a blacklisted directory
echo "Attempt to create a file inside blacklisted dir test/"
touch test/test2.txt
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} file creation inside blacklisted dir was successful"
    ((error_counter++))
fi
echo ""

# try to move blacklisted files/dirs
echo "Attempt to move blacklisted dir test/test1"
mv test/test1 mv_test1
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted dir moving was successful"
    ((error_counter++))
fi
echo ""

echo "Attempt to move blacklisted file test.txt"
mv test.txt mv_test
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} blacklisted file moving was successful"
    ((error_counter++))
fi 
echo ""

# try to create an hard link to a blacklisted file
echo "Attempt to create an hard link to blacklisted file test.txt"
ln test.txt hl_test
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} hard link creation to a blacklisted file was successful"
    ((error_counter++))
fi
echo ""

echo "Attempt to create an hard link to blacklisted file test/test1/test.txt"
ln test/test1/test.txt hl_test1
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} hard link creation to a blacklisted file was successful"
    ((error_counter++))
fi
echo ""

# try to create a symlink to a blacklisted directory
echo "Attempt to create a symlink to blacklisted dir test/"
ln -s test sym_test
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} symlink creation to a blacklisted dir was successful"
    ((error_counter++))
fi
echo ""

# try to create a symlink to a blacklisted file
echo "Attempt to create a symlink to blacklisted file test/test.txt"
ln -s test/test.txt sym_test_file
if [ $? == 0 ]; then
    echo -e "${RED}Failure:${NC} symlink creation to a blacklisted file was successful"
    ((error_counter++))
fi
echo ""

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





