<img width="1094" alt="image" src="https://user-images.githubusercontent.com/64969369/236706912-2438fae4-d4d1-4281-b0da-317a37e44877.png">


# HookPhish

[![Python](https://img.shields.io/badge/Python-3.x-yellow.svg)](https://www.python.org/) 
![Version 1.0](http://img.shields.io/badge/version-v1.0-orange.svg) ![License](https://img.shields.io/badge/license-MIT-red.svg) <img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f"> 

## Purpose
HookPhish is a Python script designed to aid in the detection of phishing websites. It performs various checks on suspected URLs to identify potential threats. The script incorporates multiple checks, namely:
- Shortened URL Check
- Tracking IP Domain Check
- Redirection Check
- Google Safe Browsing Database Check
- Real-Time Screenshot

Moreover, it utilizes the APIs of <a href="https://urlscan.io/docs/api/">urlscan.io</a> and <a href="https://www.abuseipdb.com/api">abuseipdb</a> to enhance its functionality.
Nevertheless, it's worth noting that you need to specify the corresponding api keys to use this feature.

## Demonstration
[![asciicast](https://asciinema.org/a/8QxzrtLODWlvVmmlJfOYVPMCB.svg)](https://asciinema.org/a/8QxzrtLODWlvVmmlJfOYVPMCB)

## Installation & Usage
HookPhish is a cross platform script that works with python **3.x**.
```
git clone https://github.com/0liverFlow/HookPhish
cd ./HookPhish
pip3 install -r requirements.txt
```
Then you can run it
```
python3.x HookPhish.py -u url [-f config.ini] [-v]
```

## Important Note
Though you can run this script without specifying urlscan.io and abuseipdb's api keys, it is recommended to use them in order to obtain more specific information concerning the suspected URL. To get the API keys, you need to create an account. For that, you can simply generate a temporary email using <a href="https://temp-mail.org/">tempmail.org</a> and that's it.

## API Key Configuration
After downloading the repository and getting your API Keys, you need to configure the config.ini file before executing the script. Here is how to do that:
```
cd ./HookPhish
cd config
```
Then, you need to edit the config.ini file. Feel free to use your favorite text editor. In my case, i will use vim
```
vim config.ini
```
<img width="756" alt="image" src="https://user-images.githubusercontent.com/64969369/236697555-f853d312-3bce-487e-ad42-84b6b66516b3.png"><br>

#### Warning⚠️: Do not put the API key between double quotes, only copy and paste it!

After properly configuring the API keys, you should be able to get more information using the -f/--file option followed by the config.ini file.
```
python3.x HookPhish.py -u url -f config.ini -v
```
