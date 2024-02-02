# Titleist
Watching sketchy domains as they are registered. 

This repo uses the CertStream python library to look at the names of domains being registered for DNS. It then looks at the levenshtein distance between this name
and each of many "top domains" looking for mispellings/bitflips. The threshold for triggering a message can be tweaked (currently low so it misses many but has 
fewer false positives) inside the `test_domain()` function. 

Example:
```bash
03/14/22 06:44:22 arttj.net was registered [similar to att.net? IP:23.108.179.149]
```
## Usage:
`python3 spotasquat.py`

Alternatively, the watcher.py file is a tool where you could simply log all the domains registered whose names match certain predefined substrings (I've set my own, feel free to change the code to fit your needs, maybe you want to look for "github" instances or "owa", etc.)
`python3 watcher.py`

## Logging 
Suspicious domains will be logged to a file called  `squatters.txt` by default in the directory you run the python script from. 


## Analysis
Developing some tools to create graphs using this information. There are single IPs responsible for registering many domains, and some of these turn out to be malicious. 

Assuming malicious actors stay malicioous I expect to see networks of IP blocks connected to eachother by virtue of malicious domains. Then using graph analysis should
be able to find the "most malicious" nodes as ones most connected in this graph. 

*Under development!*