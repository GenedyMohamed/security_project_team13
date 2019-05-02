# Linux Rootkit

Pre-requisites:<br />
Ubuntu OS

Steps to run the rootkit:<br />
Open terminal in project directory.<br />
run `make`<br />
run `sudo insmod rootkit.io`

Usage and configuration:<br />
run `lsmod` to view list of modules<br />
run `kill -10 0` to send a signal to unhide the rootkit module<br />
run `ps` to view currently running processes<br />
run `sleep 1000 &` to start a new process<br />
run `kill -20 <process_id>` to hide/unhide the process<br />
run `whoami` to get user<br />
run `kill -0 0` to gain root access

For further information refer back to the video.
