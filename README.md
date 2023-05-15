![image](https://github.com/0liverFlow/HookPhish/assets/64969369/1eed2645-3514-4fe1-bec2-3644dfa3e4e8)

# HookPhish
[![Python](https://img.shields.io/badge/Python-3.x-yellow.svg)](https://www.python.org/) 
![Version 1.1](http://img.shields.io/badge/version-v1.1-orange.svg) ![License](https://img.shields.io/badge/license-MIT-red.svg) <img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f"> 

## Purpose
HookPhish is a Python script designed to aid in the detection of phishing websites. It performs various checks on suspected URLs to identify potential threats. The script incorporates multiple checks, namely:
- Shortened URL Check
- Tracking IP Domain Check
- Redirection Check
- Google Safe Browsing Database Check
- Whois Lookup
- Real-Time Screenshot

Moreover, it utilizes the APIs of <a href="https://www.virustotal.com/gui/join-us">virustotal.com</a>, <a href="https://urlscan.io/docs/api/">urlscan.io</a> and <a href="https://www.abuseipdb.com/api">abuseipdb</a> to enhance its functionality.
Nevertheless, it's worth noting that you need to specify the corresponding api keys to use the API Key Integration feature.

## Demonstration
[![asciicast](https://asciinema.org/a/EkVgsFlj0vg8Wk4Z2c95hrO6u.svg)](https://asciinema.org/a/EkVgsFlj0vg8Wk4Z2c95hrO6u)

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

## Important Notes
1. You don't need administrator privileges to run this script.
2. Though you can run this script without specifying <a href="https://www.virustotal.com/gui/join-us">virustotal.com</a>, <a href="https://urlscan.io/docs/api/">urlscan.io</a> and <a href="https://www.abuseipdb.com/api">abuseipdb</a>'s api keys, it is recommended to use them in order to obtain more specific information concerning the suspected URL. To get the API keys, you need to create an account. For that, you can simply generate a temporary email using <a href="https://temp-mail.org/">tempmail.org</a> and that's it.
3. The APIs used by the script have a limited rate.
<table>
  <tr>
    <td> API </td>
    <td> Rate Limits</td>
  </tr>
  <tr>
    <td> Virustotal </td>
    <td> The Public API is limited to 500 requests per day and a rate of 4 requests per minute </td>
  </tr>
  <tr>
    <td> Urlscan.io </td>
    <td> Unlisted Scans are limited to 1000	requests per day and 60 requests per minute</td>
  </tr>
  <tr>
    <td> AbuseIPDB </td>
    <td> All free accounts have a rate limit of 1000 reports and checks per day</td>
  </tr>
</table>

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
<img width="1512" alt="image" src="https://github.com/0liverFlow/HookPhish/assets/64969369/4988edd2-a07e-47d3-9304-180a3dd25d64">

#### Warning⚠️: Do not put the API key between double quotes, only copy and paste it!

After properly configuring the API keys, you should be able to get more information using the -f/--file option followed by the config.ini file.
```
python3.x HookPhish.py -u url -f config.ini -v
```

## Latest Release Notes
- Virustotal check was added. You only need to specify the API key to use it.

## Contribution
1. If you noticed any bugs, thanks to report <a href="https://github.com/0liverFlow/HookPhish/issues">here</a> 
2. For any interesting idea, thanks to ping me at <a href="mailto:0liverFlow@proton.me">0liverFlow</a>
