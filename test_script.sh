#!/bin/bash
# Testing script for compressing in backup
set -m
echo "=========== Creating directory structure =========="
echo ""
mkdir DataToBackup
mkdir Backup
mkdir MountPoint
cd DataToBackup
mkdir Data1
cd Data1
touch file1 && tr -dc A-Za-z0-9 < /dev/urandom | head -c 20 > file1
touch file2 && tr -dc A-Za-z0-9 < /dev/urandom | head -c 200 > file2
mkdir folder1 folder2
cd folder1
mkdir folder3
touch file3 && tr -dc A-Za-z0-9 < /dev/urandom | head -c 100 > file3
touch file4 && tr -dc A-Za-z0-9 < /dev/urandom | head -c 200 > file4
cd folder3
touch file5 && tr -dc A-Za-z0-9 < /dev/urandom | head -c 20 > file5
cd ../../folder2
cp ../../../python.pdf .
#no_of_files=3;
#counter=1;
#while [[ $counter -le $no_of_files ]];
#do echo Creating file number $counter with random data;
#  dd bs=1024 count=$RANDOM skip=$RANDOM if=/dev/urandom of=random-file.$counter;
#  let "counter += 1";
#done
cd ../../..
echo "=========== Backuping initial data =========="
echo ""
python backuper init DataToBackup Backup
cp -a DataToBackup DataToBackupCopy1
echo "=========== First changing of some data =========="
cd DataToBackup
mkdir Data2
cd ..
sleep 5
echo "=========== Backuping first changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy2
echo "=========== Second changing of some data =========="
cd DataToBackup
cd Data2
mkdir folder1
cd ../..
sleep 5
echo "=========== Backuping second changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy3
echo "=========== Third changing of some data =========="
cd DataToBackup/Data2/folder1
touch file1 && tr -dc A-Za-z0-9 < /dev/urandom | head -c 20 > file1
cd ../../..
sleep 5
echo "=========== Backuping third changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy4
echo "=========== Fourth changing of some data =========="
cd DataToBackup/Data1
tr -dc A-Za-z0-9 < /dev/urandom | head -c 20 >> file1
cd ../../
sleep 5
echo "=========== Backuping fourth changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy5
echo "=========== Fifth changing of some data =========="
cd DataToBackup/Data1
rm file2
cd ../../
sleep 5
echo "=========== Backuping fifth changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy6
echo "=========== Sixth changing of some data =========="
cd DataToBackup/Data1
mv folder2 folderWithData
cd ../../
sleep 5
echo "=========== Backuping sixth changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy7
echo "=========== Seventh changing of some data =========="
cd DataToBackup/Data1
cp folderWithData/* folder1/folder3
cd ../../
sleep 5
echo "=========== Backuping seventh changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy8
echo "=========== 8th change of data: Creating symlinks =========="
cd DataToBackup/Data1
mkdir symlinks
ln -s ../folderWithData symlinks/symlink-to-folder
ln -s ../folder1/file3 symlinks/symlink-to-file
ln -s symlink-to-file symlinks/symlink-to-symlink
ln -s ../no-folder/no-file symlinks/dangling-symlink1
ln -s ../folder1/no-file symlinks/dangling-symlink2
cd ../../
sleep 5
echo "=========== Backing up 8th changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy9

echo "=========== 9th change of data: Preparing for object type changes =========="
cd DataToBackup/Data1
mkdir type-changes
cd type-changes
mkdir folder-to-file folder-to-symlink
echo "a file that will change to a symlink" > file-to-symlink
echo "a file that will change to a folder" > file-to-folder
ln -s nothing symlink-to-file
ln -s nothing symlink-to-folder
cd ..
cd ../../
sleep 5
echo "=========== Backing up 9th changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy10

echo "=========== 10th change of data: Object type changes  =========="
cd DataToBackup/Data1
cd type-changes
rmdir folder-to-file folder-to-symlink
rm file-to-symlink file-to-folder symlink-to-file symlink-to-folder
mkdir file-to-folder symlink-to-folder
echo "a file that used to be a symlink" > symlink-to-file
echo "a file that used to be a folder" > folder-to-file
ln -s nothing file-to-symlink
ln -s nothing folder-to-symlink
cd ../../../
sleep 5
echo "=========== Backing up 10th changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy11

echo "=========== 11th change of data: No change after type changes  =========="
sleep 5
echo "=========== Backing up 11th changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy12

echo "=========== 12th change of data: Cleanup after 8--11 =========="
cd DataToBackup/Data1
rm -r symlinks
rm -r type-changes
rm folder1
mv real-folder1 folder1
rm folderWithData
mv real-folderWithData folderWithData
cd ../../
sleep 5
echo "=========== Backing up 12th changed data =========="
echo ""
python backuper backup DataToBackup Backup
cp -a DataToBackup DataToBackupCopy13

#echo "=========== Mounting FUSE file system of backuped data =========="
#echo ""
#python myfuse.py Backup MountPoint &
#sleep 10
#cd MountPoint
#DIRS=(`ls -d */`)
##for DIR in $DIRS
##do
##    echo ${DIR}
##done
#for i in {1..11}
#do
#    echo "========== diff off DataToBackupCopy" ${i} " and " ${DIRS[$i - 1]} " =========="
#    diff -r ../DataToBackupCopy${i} ${DIRS[$i - 1]}
#    sleep 5
#done
#sleep 5
#kill %1
#sleep 5

echo "=========== Recovering backed-up data =========="
cd Backup/target/backups
DIRS=(`ls`)
cd ../../..
cd MountPoint
for i in {1..13}
do
    mkdir DataToBackupCopy${i}
    python ../backuper recover DataToBackupCopy${i} ../Backup ${DIRS[$i - 1]}
    sleep 5
done
for i in {1..13}
do
    echo "========== diff off DataToBackupCopy" ${i} " and " ${DIRS[$i - 1]} " =========="
    diff -r ../DataToBackupCopy${i} DataToBackupCopy${i}
    sleep 5
done

echo "=========== Removing all created data =========="
cd ..
rm -r DataToBackup
for i in {1..13}
do
    rm -r DataToBackupCopy$i
done
rm -r Backup
rm -r MountPoint
