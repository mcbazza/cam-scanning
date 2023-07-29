# cam-scanning
Place to store my various exposed IoT cam-scanning work and info

## Nmap script
[bazcam-scanner.nse](nmap/bazcam-scanner.nse) - This is an Nmap script that will aid you in detecting and pulling down useful into from cheapo IP-Cams that are likely exposed via UPnP, where the cam interface is then also publicly exposed.
There's no brute-forcing. It just attempts to check if the cam's admin i/f is exposed on 80/tcp, and if so, will tell you if certain files are present.

Use it like this:
```
nmap -p80,554,1935 -sV --script bazcam-scanner <target>
```
**NB:** Finding ports 80,554 and 1935 are a (almost) sure-fire way of finding that the cheapo IP-cam is exposed due to UPnP being '`on`' by default (both in the IP-cam settings, and at the broadband router). The script doesn't _need_ UPnP to be exposing stuff. It just means that more info from the cam is available, if it is.

### Disclaimer:
Don't do crimes. If you get into trouble using this, it wasn't my fault. This was your warning. Also, UPnP was a mistake. You should turn it off, and go check your parents/etc. And stop using cheap shi#ty IP cams that are >10yrs old.

### Testing this script:

This Shodan query will find you lots of publicly exposed cams for you to test against.
https://www.shodan.io/search?query=has_screenshot%3Atrue+port%3A554+server%3A+hipcam

---

# More, coming soon...
