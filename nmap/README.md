# Nmap scanning and capturing still images

Script: `bazcam-scanner.nse` \
This is the "scan-only" script.

Script: `bazcam-scanner-capture.nse` \
This is a cut-down version of the script (doesn't attempt to pull down any exposed info), and instead will attempt to capture a still image and save it to a folder. \
In order to use this version of the Nmap script you'll need to do some setup first.

---

## Setting up Environment for script to capture images

Please note that the following is based upon setting the environment up in a fresh Ubuntu 22.04 LTS VM. \
A virtual Python environment is utilised to ensure that we can install the required modules, and so that any exernal updates will then not interfere with them.

### Installing the required Linux packages
```
sudo apt install nmap python3-pip python3.10-venv -y
```
### Create the environment
```
mkdir bazcam-scanner
cd bazcam-scanner
python3 -m venv env
```

### Activate the virtual Python environment
```
source env/bin/activate
```

### Install python modules (into the virtual Python environment)
```
pip3 install -r requirements.txt
```

### How to use the Nmap script in association with the Python script
For this example there is an Hipcam-based IP Camera on `192,168.1.150` where video is being exposed without authentication on `554/tcp`.

The required `bazcam-scanner-capture.py` file is saved to: `/home/bazza/bazcam-scanner`

The captured image is to be saved to: `/home/bazza/bazcam-scanner/` \
A captured image filename, for this capture, would be: `192.168.1.150-554.jpg`

**NB:** If you invoke Nmap via `sudo` you should send full paths to the Nmap script arguments
```
nmap -Pn -p554 --script ./bazcam-scanner-capture.nse --script-args 'scriptdir=/home/bazza/bazcam-scanner,images=/home/bazza/bazcam-scanner/' 192.168.1.150
```
---
## Using Shodan CLI in association with `bazcam-scanner-capture` scripts

This is a demo of how you can use the Shodan.io API / CLI, in order to get a list of IPs that you'd then like to capture images from.

**NB:** You're going to need a Shodan account, along with the CLI installed to your environment and configured with your API key.

### Search + download the results for all Hipcam cameras that Shodan has discovered in GB.
```
shodan download gb-cams "country:gb port:554 "200 OK" Server: Hipcam"
```

### Parse the downloaded search results and save the list of IPs to a file
```
shodan parse --fields ip_str gb-cams.json.gz >gb-cams.txt
```

### Using the list of IPs to scan against
```
nmap -Pn -p554 --script ./bazcam-scanner-capture.nse --script-args 'scriptdir=/home/bazza/bazcam-scanner,images=/home/bazza/bazcam-scanner/' -iL gb-cams.txt
```
---
## Disclaimer
Don't do crime. Disable UPnP. The 's' in IoT stands for 'Security'. If your devices are no longer supported, maybe you should replace them? Be curious. Hack the Planet.
