-- AUTHOR: Stephen McGill, 2017
-- Usage: luajit test_pcap.lua FILENAME.pcap
-- Description: Parse PCAP files from tcpdump

local lib = {}

------------------
-- Dependencies
local ffi = require'ffi'
local mmap = require'mmap'
------------------

------------------
-- PCAP file format: http://wiki.wireshark.org/Development/LibpcapFileFormat/
ffi.cdef[[
typedef struct pcap_file {
  /* file header */
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_file;

/* This is the header of a packet on disk.  */
typedef struct pcap_record {
  /* record header */
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_usec;        /* timestamp microseconds */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
} pcap_record;
]]
------------------
local record_sz = ffi.sizeof'struct pcap_record'
local header_sz = ffi.sizeof'pcap_file'
-- Export
lib.record_sz = record_sz
lib.header_sz = header_sz

------------------
-- Iterator on the entries
function lib.entries(fname)
  local ptr, sz = mmap.open(fname)
  local ptr_end = ptr + sz
  local header = ffi.cast("pcap_file *", ptr)
  ptr = ptr + header_sz
  if header.magic_number ~= 0xA1B2C3D4 then
    return false, string.format('Bad magic number: %X', header.magic_number)
  end
  local npkt = (sz - ffi.sizeof'pcap_file') / ffi.sizeof('pcap_record')
  return coroutine.wrap(function(t)
    local cnt = 0
    while ptr < ptr_end do
      cnt = cnt + 1
      local ptr_record = ffi.cast('pcap_record*', ptr)
      local t = ptr_record.ts_sec + ptr_record.ts_usec / 1e6
      local incl_len = ptr_record.incl_len
      -- local orig_len = ptr_record.orig_len
      local packet = ptr + record_sz
      coroutine.yield(t, {packet, incl_len}, ptr_record, record_sz + incl_len)
      ptr = packet + incl_len
    end
    mmap.close(ptr, sz)
    return
  end), header, header_sz
end

return lib