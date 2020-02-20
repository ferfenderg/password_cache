# password_cache

pip install regex pexpect keyutils getpass3 argparse logging

This script uses keyctl to temporarily cache a password. 
This isn't a replacement for a password management system nor an effective replacement for sudo escalation.
It's good practice to use the name of the code as the key prefix. This would make it easier for you to code around it

WARNING: This is not production safe! It stores the password in unencrypted in memory so it's vulnerable to a number of memory based attacks
