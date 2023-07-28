description = [[
Checks an IP to see if it's a cheapo generic IP cam that is hooked up via UPnP and exposing intel via the www interface.
]]

---
-- @usage
-- nmap -p80,554,1935 -sV --script bazcam-scanner <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp   open     http
-- | bazcam-scanner-new: 
-- |   Date: Thu, 27 Jul 2023 22:08:43 GMT
-- |   Last-Modified: Thu, 27 Jul 2023 22:08:43 GMT
-- |   Connection: close
-- |   Cache-Control: no-cache,no-store
-- |   WWW-Authenticate: Basic realm="index.html"
-- |   
-- |   /log/wifi.mac             : xx:xx:xx:xx:xx:x
-- |   /log/netflag.dat          : 
-- |   /log/proc.tmp             : 
-- |   /log/sd_flag              : 
-- |   /log/sdt.ok               : 
-- |   /log/sensor.conf          : 
-- |   /log/syslog.txt           : 
-- |       username              : 
-- |   /log/th3ddns.dat          : 
-- |   /log/upnpmap.dat          : 
-- |   /log/wifi.type            : 
-- |   /log/wpa.conf             : 
-- |   /log/wf129                : 
-- |_  /log/config_backup.bin    : 
-- 81/tcp   filtered hosts2-ns
-- 554/tcp  open     rtsp
-- |_bazcam-scanner-new: Hipcam RealServer/V1.0
-- 1935/tcp open     rtmp
---

author = "mcbazza <twitter.com/mcbazza>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

local http = require "http"
local rtsp = require "rtsp"
local shortport = require "shortport"
local stringaux = require "stringaux"
local stdnse = require "stdnse"
local string = require "string"

local FILE_URIS = {
    "/log/wifi.mac",
    "/log/netflag.dat",
    "/log/proc.tmp",
    "/log/sd_flag",
    "/log/sdt.ok",
    "/log/sensor.conf",
    "/log/syslog.txt",
    "/log/th3ddns.dat",
    "/log/upnpmap.dat",
    "/log/wifi.type",
    "/log/wpa.conf",
    "/log/wf129",
    "/log/config_backup.bin"
}

-- The Head Section --

-- The Rule Section --
portrule = function(host, port)
    return port.protocol == "tcp"
            and ( (port.number == 80) 
              or (port.number == 81) 
              or (port.number == 8080) 
              or (port.number == 554) 
              or (port.number == 1935))
            and port.state == "open"
end

-- The Action Section --
action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local useget = stdnse.get_script_args(SCRIPT_NAME..".useget")
  local request_type = "HEAD"
  local status = false
  local result
  local response

  if (port.number == 554) then
    local path = '*'
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
      local opts = response.headers['Server']
      return stringaux.strsplit(",%s*", opts), opts
    end
  end

  if ((port.number == 80) or (port.number == 81) or (port.number == 8080)) then
    -- Check if the user didn't want HEAD to be used
    if(useget == nil) then
      -- Try using HEAD first
      status, result = http.can_use_head(host, port, nil, path)
    end

    -- If head failed, try using GET
    if(status == false) then
      stdnse.debug1("HEAD request failed, falling back to GET")
      result = http.get(host, port, path)
      request_type = "GET"
    end

    if not (result and result.status) then
      return fail("Header request failed")
    end

    for i, uri in ipairs(FILE_URIS) do

      local uri = "" .. uri
      local response = http.get(host, port, uri)
      if ( response.status == 200 ) then

        if uri == "/log/config_backup.bin" then
          uri_response = "Found!"
        else
          uri_response = response.body
          uri_response = string.gsub(uri_response, "[\n\r]", "") 
        end

      elseif ( response.status == 404 ) then
        uri_response = "not found"
      else
        uri_response = "?"
      end

      table.insert(result.rawheader, string.format("%-25s : %s", uri, string.sub(uri_response,1,100)) )

      if uri == "/log/syslog.txt" then      
        syslog_user = string.match(response.body, ".*user(.*) login.*")
        syslog_user = string.gsub(syslog_user, "[()]", "") 

        table.insert(result.rawheader, string.format("%-25s : %s", "    username", string.sub(syslog_user,1,100)) )
      end

    end

    return stdnse.format_output(true, result.rawheader)
  end

  return

end
