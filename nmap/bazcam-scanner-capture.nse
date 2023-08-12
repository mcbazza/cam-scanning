description = [[
A minimal version of bazcam-scanner.nse that simply captures an image.

It accepts 2x Nmap script arguments:
scriptdir = the directory where Nmap can find the `bazcam-scanner-capture.py` script.
images = the directory where the captured images are to be saved to.

NB: if you run Nmap as `sudo`, I recommend that you give full paths.

Script : bazcam-scanner-capture.nse
Author : Bazza
Contact: twitter.com/mcbazza
Credits: My fellow PwnDefend Discordians
]]

---
-- @usage
-- nmap -Pn -p554 --script ./bazcam-scanner-capture.nse --script-args 'scriptdir=/home/bazza/bazcam-scanner,images=/home/bazza/bazcam-scanner/pt-images/' -iL pt-cams.txt
--
-- @output
-- PORT   STATE SERVICE REASON
-- 554/tcp  open     rtsp
-- |_bazcam-scanner-capture: Hipcam RealServer/V1.0
---

author = "mcbazza <twitter.com/mcbazza>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

local rtsp = require "rtsp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
-- local string = require "string"

portrule = shortport.port_or_service(554, "rtsp", "tcp", "open")

-- The Action Section --
action = function(host, port)
  local path = stdnse.get_script_args('bazcam-scanner-capture.path') or '*'
  local scriptdir = stdnse.get_script_args('bazcam-scanner-capture.scriptdir') or ''
  local imagedir = stdnse.get_script_args('bazcam-scanner-capture.images') or 'cams/'

  local helper = rtsp.Helper:new(host, port)
  local status = helper:connect()
  if ( not(status) ) then
    stdnse.debug2("ERROR: Failed to connect to RTSP server")
    return
  end

  local response
  status, response = helper:options(path)
  helper:close()
  if ( status ) then
    -- Spawn process to grab image from the IP

    -- This one uses an & to run the command and spawn/detach. Not had great success with this method.
    -- os.execute("cd " .. scriptdir .. " ; . env/bin/activate ; python3 bazcam-scanner-capture.py -i " .. host.ip .. " -d " .. imagedir ..' &')
    -- This one runs in syncronously (waits for process to complete)
    os.execute("cd " .. scriptdir .. " ; . env/bin/activate ; python3 bazcam-scanner-capture.py -i " .. host.ip .. " -d " .. imagedir ..' &')

    local opts = response.headers['Public']
    return stringaux.strsplit(",%s*", opts), opts
  end
end

