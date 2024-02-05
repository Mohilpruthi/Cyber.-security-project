#!/bin/bash

clear

BLACK=`tput setaf 0`
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
WHITE=`tput setaf 7`
BOLD=`tput bold`
RESET=`tput sgr0`

echo """${BOLD}${BLUE}
  ______             __              ______                              __    __         ______  
 /      \           /  |            /      \                            /  \  /  |       /      \ 
/$$$$$$  | __    __ $$ |____       /$$$$$$  |  _______   ______         $$  \ $$ |      /$$$$$$  |
$$ \__$$/ /  |  /  |$$      \      $$ \__$$/  /       | /      \        $$$  \S$ |      $$ \__$$/ 
$$      \ $$ |  $$ |$$$$$$$  |     $$      \ /$$$$$$$/  $$$$$$  |       $$$$  $$ |      $$      \ 
 $$$$$$  |$$ |  $$ |$$ |  $$ |      $$$$$$  |$$ |       /    $$ |       $$ $$ $$ |       $$$$$$  |
/  \__$$ |$$ \__$$ |$$ |__$$ |     /  \__$$ |$$ \_____ /$$$$$$$ |       $$ |$$$$ |      /  \__$$ |
$$    $$/ $$    $$/ $$    $$/______$$    $$/ $$       |$$    $$ |______ $$ | $$$ |______$$    $$/ 
 $$$$$$/   $$$$$$/  $$$$$$$//      |$$$$$$/   $$$$$$$/  $$$$$$$//      |$$/   $$//      |$$$$$$/  
                            $$$$$$/                             $$$$$$/          $$$$$$/          
                                             
                                                               
                                ${RED}       TR3-ASTRA ${RESET}
"""


sudo apt-get install python3

sudo apt-get install python 

sudo apt-get install python3-pip

sudo apt-get install python-pip

sudo apt-get install libgcc1

sudo pip install dnspython 2>/dev/null

sudo pip3 install requests

sudo pip3 install argparse

sudo pip3 install bs4

sudo apt-get install amass
pip3 install dnsrecon sublist3r
pip3 install tqdm
pip3 install httpx aiodns
pip3 install tabulate

sudo chmod +x Sub_Sca_N_S.py

mkdir /usr/share/Sub_Sca_N_S

cp default.txt /usr/share/Sub_Sca_N_S/

sudo cp Sub_Sca_N_S.py /usr/bin/Sub_Sca_N_S

clear

