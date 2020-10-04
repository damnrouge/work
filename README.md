# compile as 32 bit
apt-get install libc6-i386
sudo apt-get install g++-multilib
gcc -m32 bof.c -o bof


