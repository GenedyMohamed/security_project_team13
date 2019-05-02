Pre-requisites:
Ubuntu OS

Steps to run the rootkit:
Open terminal in project directory.
run `make`
run `sudo insmod rootkit.io`

Usage and configuration:
run `lsmod` to view list of modules
run `kill -10 0` to send a signal to unhide the rootkit module
run `ps` to view currently running processes
run `sleep 1000 &` to start a new process
run `kill -20 <process_id>` to hide/unhide the process
run `whoami` to get user
run `kill -0 0` to gain root access

For further information refer back to the video.