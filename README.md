CatDevRandom.hs is a stack script which is an implementation of a CSPRNG (Cryptographically Secure Random Number Generator). It gathers entropy using data from network interfaces (names, ip addresses, mac addresses), and processes (pids, process names, times since rebooting). The implementation of the CSPRNG is based off of Fortuna, described in the following link: https://www.schneier.com/academic/paperfiles/fortuna.pdf

Instructions for running (on Unix/Linux systems):

1) Open your terminal, and make sure CatDevRandom.hs, configure_stack.sh, 
cat_dev_random.sh are all in the same directory.

2) Go to haskellstack.org, and follow the instructions to download stack
for your platform: https://docs.haskellstack.org/en/stable/install_and_upgrade/

2) Run the following commands for permissions:
  i)  chmod +x configure_stack.sh
  ii) chmod +x cat_dev_random.sh

3) Run ./configure_stack.sh, to get stack and all the necessary dependencies
ready.

4) Run ./cat_dev_random.sh, and enjoy the stream of random bytes! Press ctrl-z 
if you want to exit.
