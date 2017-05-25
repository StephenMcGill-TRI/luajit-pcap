#!/usr/bin/env luajit

-- AUTHOR: Stephen McGill, 2017
-- Usage: luajit test_pcap.lua FILENAME.pcap
-- Description: Iterate through packets from pcap log files

local pcap = require("pcap")

local filename = assert(arg[1], 'Please provide a filepath')

for t, entry in pcap.entries(filename) do
  print(t, unpack(entry))
end
