#!/usr/bin/python3
"" A Python script to poll the IP of a Hipcam-like IP Cam and capture an image.

Script : bazcam-scanner-capture.py
Author : Bazza
Contact: twitter.com/mcbazza
Credits: My fellow PwnDefend Discordians

This Python script is intended to be used in association with the `bazcam-scanner-capture.nse` Nmap script.
If the Nmap script detects an open Hipcam camera on 554/tcp, it executes this python script.
It passes in two variables:
  ip = the IP of the camera
  dir = the directory where any captured image should be saved
This script then attempts to connect to the camera and capture a still image.

"""

import os
import sys, getopt, socket, cv2
from colorama import Fore, Back, Style

# the root of where the images are stored.
image_root = './'

def SaveImageFromRTSP(ip, uri, port):
  cap = cv2.VideoCapture('rtsp://'+ip+':'+port+uri)

  ret, frame = cap.read()

  if cap.isOpened():
    _,frame = cap.read()
    cap.release() #releasing camera immediately after capturing picture
    if _ and frame is not None:

      # Added image_root
      path = image_root

      # Image filename will be: x.x.x.x-554.jpg
      filename = ip+'-'+port+'.jpg'

      # Check whether the specified path exists or not
      isExist = os.path.exists(path)

      if not isExist:
        # Create the folder if needed
        os.makedirs(path)

      # Save the captured image
      cv2.imwrite(path+'/'+filename, frame)
      print('Saved image: '+Fore.GREEN+path+filename+Style.RESET_ALL)

      cv2.destroyAllWindows()

      return True
    else:
      cv2.destroyAllWindows()
      return False
  else:
    cap.release()
    cv2.destroyAllWindows()
    return False

def check_ip(ipaddr):

  # URI to capture the image from.
  # rtsp://x.x.x.x:554/1
  camRTSP = 'rtsp://'+ipaddr+':554/1'

  get_cam_image = SaveImageFromRTSP(ipaddr, '/1','554')

  return True

def main(argv):

  global image_root

  try:
    opts, args = getopt.getopt(argv,"hi:d:",["ipaddr=","images="])
  except getopt.GetoptError:
    print ('bazcam-scanner-capture.py -i <IP to check> [-d <directory to save images to>')
    sys.exit(2)

  for opt, arg in opts:
    if opt == '-h':
      print ('bazcam-scanner-capture.py -i <IP to check>')
      sys.exit()
    elif opt in ("-d", "--images"):
      # This is the folder to save the images to
      image_root = arg
    elif opt in ("-i", "--ip"):
      # We have a single IP to check
      ipaddr =  arg

  check_status = check_ip(ipaddr)

if __name__ == "__main__":

  main(sys.argv[1:])
