# URLCheck

```
$ urlcheck -h
usage: urlcheck [-h] [-f FILE] [-g GSB_API_KEY] [-u URLSCAN_API_KEY] [-p PROXY] [-t TIMEOUT]

Checks URLs against Google Safe Browsing and checks their status

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Defaults to /dev/stdin
  -g GSB_API_KEY, --gsb_api_key GSB_API_KEY
                        Defaults to GSB_API_KEY environment variable
  -u URLSCAN_API_KEY, --urlscan_api_key URLSCAN_API_KEY
                        Defaults to URLSCAN_API_KEY environment variable
  -p PROXY, --proxy PROXY
                        https proxy to use (eg. 20.229.33.75:8080)
  -t TIMEOUT, --timeout TIMEOUT
                        http timeout (defaults to 5)
```
