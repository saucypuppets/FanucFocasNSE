local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates a Fanuc CNC controller exposing FOCAS 2 over Ethernet (TCP/8193).

The script performs read-only FOCAS queries for system information, machine
status, active alarms, active program details, and the CNC program directory.
It never sends write or control requests.
]]

---
-- @usage
-- nmap -p 8193 --script fanuc-focas-enum <target>
-- nmap -p 8193 --script fanuc-focas-enum \
--      --script-args fanuc-focas-enum.timeout=10s,fanuc-focas-enum.maxprogs=200 \
--      <target>
--
-- @args fanuc-focas-enum.timeout    socket timeout (default 5s)
-- @args fanuc-focas-enum.maxprogs   cap on programs to list (default 100)
-- @args fanuc-focas-enum.maxalarms  cap on alarm messages to read (default 10)
--
-- @output
-- PORT     STATE SERVICE
-- 8193/tcp open  focas
-- | fanuc-focas-enum:
-- |   system:
-- |     model:        0i-MD
-- |     control:      0i
-- |     machine:      Milling
-- |     series:       D4F1
-- |     version:      37.0
-- |     axes:         03
-- |     capabilities: i-Series
-- |   status:
-- |     mode:       MDI
-- |     run_state:  STOP
-- |     motion:     none
-- |     aux_signal: none
-- |     alarm:      ALARM
-- |     emergency:  EMERGENCY STOP
-- |     edit:       not editing
-- |   alarms:
-- |     bits_set:  parameter switch on; servo alarm; spindle alarm
-- |     messages:
-- |       [0] alarm=100   group=0 axis=0  PARAMETER ENABLE SWITCH ON
-- |       [1] alarm=5136  group=6 axis=0  FSSB:NUMBER OF AMP. IS INSUFFICIENT
-- |       [2] alarm=1999  group=9 axis=0  SPINDLE CONTROL ERROR
-- |       [3] alarm=1220  group=9 axis=1  (S)NO SPINDLE AMP.
-- |   active_program:
-- |     running_O:    O5112
-- |     main_O:       O5112
-- |     sequence:     0
-- |     program_name: O5112
-- |   programs (16 in CNC memory):
-- |     O0090       500 B  ()
-- |     O0249      1500 B  (SHAVE 5MM 73.1)
-- |     O0545       500 B  ()
-- |     O0671       500 B  ()
-- |     O0703      1000 B  ()
-- |     O1993      3500 B  (OPEN BORE 87.1 CHAMFER)
-- |     O1994      4500 B  (OPEN BORE 130.2 CHAMFER)
-- |_    ...

categories = {"discovery", "safe", "version"}
author = "saucypuppets"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

-- ---------------------------------------------------------------------------
-- Protocol frame markers (all multi-byte fields are big-endian)
-- ---------------------------------------------------------------------------

local FRAME_MARKER = "\xA0\xA0\xA0\xA0"

local FRAME_LINK_START = 0x0101
local FRAME_LINK_READY = 0x0102
local FRAME_LINK_STOP  = 0x0201
local FRAME_READ_BLOCK = 0x2101
local FRAME_READ_REPLY = 0x2102

-- Read query identifiers used below.
local QUERY_MACHINE_PROFILE  = 0x0018
local QUERY_RUNTIME_STATE    = 0x0019 
local QUERY_ALARM_FLAGS      = 0x001A
local QUERY_ACTIVE_PROGRAMS  = 0x001C
local QUERY_SEQUENCE_NUMBER  = 0x001D
local QUERY_ALARM_TEXT       = 0x0023
local QUERY_ACTIVE_NAME      = 0x00CF
local QUERY_PROGRAM_CATALOG  = 0x0006
local QUERY_STATE_AUX_1      = 0x00E1
local QUERY_STATE_AUX_2      = 0x0098

local RESULT_TEXT = {
  [   0] = "ok",
  [   1] = "unsupported request",
  [   2] = "bad length",
  [   3] = "bad number",
  [   4] = "out of range",
  [   5] = "bad data",
  [   6] = "option unavailable",
  [   7] = "protected",
  [   8] = "socket error",
  [   9] = "missing parameter",
  [  13] = "option unavailable",
  [  14] = "data server error",
  [  -1] = "busy",
  [  -2] = "bad session",
  [  -7] = "version mismatch",
  [  -8] = "unexpected response",
  [ -16] = "serial bus error",
  [ -17] = "protocol error",
}

local function result_label(code)
  return RESULT_TEXT[code] or ("rc=" .. tostring(code))
end

-- Alarm bit names used by common i-Series controllers.
local ALERT_FLAG_LABELS = {
  [0]  = "parameter switch on",
  [1]  = "power-off parameter pending",
  [2]  = "I/O error",
  [3]  = "foreground program alarm",
  [4]  = "overtravel or external data",
  [5]  = "overheat",
  [6]  = "servo alarm",
  [7]  = "data I/O error",
  [8]  = "macro alarm",
  [9]  = "spindle alarm",
  [10] = "other alarm",
  [11] = "malfunction prevention",
  [12] = "background program alarm",
  [13] = "synchronized error",
  [15] = "external alarm message",
  [19] = "PMC error",
}

-- Labels used when decoding responses
local PATH_MODE_LABELS = {
  [0]="MDI", [1]="MEM", [2]="(none)", [3]="EDIT", [4]="HND",
  [5]="JOG", [6]="T/JOG", [7]="T/HND", [8]="INC", [9]="REF", [10]="RMT",
}
local RUN_LABELS = {
  [0]="STOP", [1]="HOLD", [2]="START", [3]="MSTR (tool change)",
  [4]="(none)", [5]="(none)", [6]="(none)", [7]="(none)",
}
local MOTION_LABELS = {
  [0]="none", [1]="motion", [2]="dwell", [3]="wait (TT multi-path)",
}
local AUX_SIGNAL_LABELS = {
  [0]="none", [1]="FIN",
}
local EDIT_LABELS = {
  [0]="not editing", [1]="EDIT", [2]="SEARCH", [3]="OUTPUT",
  [4]="INPUT", [5]="COMPARE", [6]="LABEL SKIP", [7]="RESTART",
  [8]="HPCC", [9]="PTRR", [10]="RVRS", [11]="RTRY", [12]="RVED",
  [13]="HANDLE", [14]="OFFSET", [15]="WORK SHIFT", [16]="AICC",
  [17]="MEM-CHK", [18]="(reserved)", [19]="AICC2", [20]="(reserved)",
}

-- Labels used when decoding the controller profile.
local MACHINE_KIND_LABELS = {
  M="Milling", T="Turning", MM="Milling 2-path", TT="Turning 2/3-path",
  MT="Turning w/ compound machining",
  P="Punch press", G="Grinding", L="Laser", W="Wire EDM",
}
-- Control family codes. The 16/18/21 families share their code between
-- non-i and i-Series controllers
local CONTROL_FAMILY_LABELS = {
  ["0"]="0i",  ["15"]="15/15i", ["16"]="16/16i", ["18"]="18/18i", ["21"]="21/21i",
  ["30"]="30i", ["31"]="31i",   ["32"]="32i",    ["35"]="35i",
  ["PD"]="Power Mate i-D", ["PH"]="Power Mate i-H", ["PM"]="Power Motion i",
}
-- Profile bits 8-15 = model letter. Bit-value 5 is intentionally skipped
-- Fanuc never made a type E?
local MODEL_SUFFIX_LABELS = { [1]="A", [2]="B", [3]="C", [4]="D", [6]="F" }

-- Trims whitespace from the beginning and end of a string
local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end


--Sanitizes value to an integer if it isn't
local function clamp_int(value, default, min_value, max_value)
  local n = tonumber(value)
  if not n then return default end
  n = math.floor(n)
  if n < min_value then return min_value end
  if max_value and n > max_value then return max_value end
  return n
end

-- ---------------------------------------------------------------------------
-- Socket / framing helpers (each used by multiple call sites)
-- ---------------------------------------------------------------------------

-- Responses from the CNC control contains two layers: a 10 byte outer frame header
-- which also contains the length of the following payload of information. 
-- We're reading the response from the CNC via NMAP, and our request for the payload
-- from NMAP happens asynchonously from the request. If the CNC returned information 
-- really fast, NMAP may hand us more information than what the outer layer says to 
-- expect. If we hard-code our parser to only take what the outer frame header
-- says to expect, we may miss additional information. 
-- Without recv_exact and recv_leftover, the script can get stuck like this:
-- 1. Ask for 10 bytes.
-- 2. Nmap returns 46 bytes.
-- 3. Script parses first 10 as header.
-- 4. Script asks for 36-byte payload.
-- 5. But those 36 bytes were already returned in step 2.
-- 6. Script waits forever or times out.

--Creates a table which is used later to store all the data sent by the response.
local recv_leftover = setmetatable({}, { __mode = "k" })

local function recv_exact(sock, n)
  local buf = recv_leftover[sock] or ""
  while #buf < n do
    local status, chunk = sock:receive_bytes(n - #buf)
    if not status then
      recv_leftover[sock] = buf
      return nil, ("short read (need %d, got %d): %s"):format(n, #buf, tostring(chunk))
    end
    buf = buf .. chunk
  end
  recv_leftover[sock] = buf:sub(n + 1)
  return buf:sub(1, n)
end

local function recv_frame(sock)
  local hdr, err = recv_exact(sock, 10)
  if not hdr then return nil, err end
  if hdr:sub(1, 4) ~= FRAME_MARKER then
    return nil, ("bad magic: %s"):format(stdnse.tohex(hdr:sub(1, 4)))
  end
  local flags, opcode, plen = string.unpack(">I2I2I2", hdr, 5)
  local payload = ""
  if plen > 0 then
    payload, err = recv_exact(sock, plen)
    if not payload then return nil, err end
  end
  return { flags = flags, opcode = opcode, payload = payload }
end

local function pack_frame(opcode, payload)
  return FRAME_MARKER .. string.pack(">I2I2I2", 0x0001, opcode, #payload) .. payload
end

-- ---------------------------------------------------------------------------
-- Session setup opens two connections; only the second carries data.
-- ---------------------------------------------------------------------------

local function open_control_channel(host, port, ordinal, timeout_ms)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout_ms)
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then return nil, "connect failed: " .. tostring(err) end
  local hs = FRAME_MARKER .. string.pack(">I2I2I2I2",
                                  0x0001, FRAME_LINK_START, 0x0002, ordinal)
  local sent, serr = sock:send(hs)
  if not sent then sock:close(); return nil, "handshake send: " .. tostring(serr) end
  local resp, rerr = recv_frame(sock)
  if not resp then sock:close(); return nil, "handshake recv: " .. tostring(rerr) end
  if resp.flags ~= 0x0004 or resp.opcode ~= FRAME_LINK_READY then
    sock:close()
    return nil, ("unexpected handshake reply: flags=0x%04x opcode=0x%04x"):format(
                  resp.flags, resp.opcode)
  end
  return sock
end

local function close_control_channel(sock)
  if not sock then return end
  pcall(function()
    sock:send(pack_frame(FRAME_LINK_STOP, ""))
    recv_frame(sock)
  end)
  sock:close()
end

-- ---------------------------------------------------------------------------
-- Standard FOCAS envelope:
--
--   [0]  subreq_count = 1     (uint16)
--   [2]  inner_len    = 28    (uint16)
--   [4]  flag1        = 1     (uint16)
--   [6]  flag2        = 1     (uint16)
--   [8]  query_id              (uint16)
--   [10] arg1                  (int32, signed)   -- 4 bytes!
--   [14] arg2                  (int32)
--   [18] arg3                  (int32)
--   [22] arg4                  (int32)
--   [26] arg5                  (int32)
--
-- ---------------------------------------------------------------------------

local function pack_envelope(query_id, args)
  args = args or {}
  while #args < 5 do args[#args + 1] = 0 end
  local body = string.pack(">I2I2I2I2I2", 0x0001, 28, 0x0001, 0x0001, query_id)
  for i = 1, 5 do
    body = body .. string.pack(">i4", args[i])
  end
  return body
end

-- Parses standard response
--   [0]  subreq_count (=1 for non-compound calls)   uint16
--   [2]  inner_len                                  uint16
--   [4]  flag1 (=1)                                 uint16
--   [6]  flag2 (=1)                                 uint16
--   [8]  query_id echo                              uint16
--   [10] rc                                         int16  (signed)
--   [12] err_no                                     int16
--   [14] err_dtno                                   int16
--   [16] data_len                                   uint16
--   [18..18+data_len) data
local function parse_response(payload)
  if #payload < 18 then
    return nil, ("response payload too short (%dB)"):format(#payload)
  end
  local subreq_count = string.unpack(">I2", payload, 1)
  local inner_len    = string.unpack(">I2", payload, 3)
  local query_id     = string.unpack(">I2", payload, 9)
  local rc           = string.unpack(">i2", payload, 11)
  local err_no       = string.unpack(">i2", payload, 13)
  local err_dtno     = string.unpack(">i2", payload, 15)
  local data_len     = string.unpack(">I2", payload, 17)
  if data_len > #payload - 18 then
    return nil, ("response data_len %d exceeds available payload %d"):format(
                  data_len, #payload - 18)
  end
  local data         = payload:sub(19, 18 + data_len)
  return {
    subreq_count = subreq_count, inner_len = inner_len,
    query_id = query_id, rc = rc,
    err_no = err_no, err_dtno = err_dtno,
    data_len = data_len, data = data,
  }
end

local function call(sock, request_payload)
  local ok, err = sock:send(pack_frame(FRAME_READ_BLOCK, request_payload))
  if not ok then return nil, "send: " .. tostring(err) end
  local resp, rerr = recv_frame(sock)
  if not resp then return nil, "recv: " .. tostring(rerr) end
  if resp.flags ~= 0x0004 or resp.opcode ~= FRAME_READ_REPLY then
    return nil, ("bad reply: flags=0x%04x opcode=0x%04x"):format(resp.flags, resp.opcode)
  end
  return parse_response(resp.payload)
end

local ZERO_ARGS = {0, 0, 0, 0, 0}

local function request_query(sock, query_id, args)
  return call(sock, pack_envelope(query_id, args or ZERO_ARGS))
end

local function clean_text(s)
  s = (s or ""):gsub("%z.*$", ""):gsub("%c", " ")
  return trim(s)
end

local function label_value(labels, raw)
  return labels[raw] or ("? (raw=" .. tostring(raw) .. ")")
end

local function format_o_number(n)
  return ("O%04d"):format(n or 0)
end

local function detect_profile_layout(data, family_code)
  local profile_bits = string.unpack(">I2", data, 1)
  local axis_word = string.unpack(">I2", data, 3)

  -- Series 15 non-i stores the axis field as ASCII, not a binary short.
  local legacy_15_layout = (family_code == "15" and (axis_word == 0 or axis_word > 256))
  return profile_bits, axis_word, legacy_15_layout
end

local function friendly_model(family_code, machine_code, i_series, model_letter, legacy_15_layout)
  local machine_letter = (#machine_code > 0) and machine_code:sub(1, 1) or ""

  if family_code == "0" then
    return "0i-" .. machine_letter .. (model_letter or "")
  elseif family_code == "30" or family_code == "31"
      or family_code == "32" or family_code == "35" then
    return family_code .. "i" .. (model_letter and ("-" .. model_letter) or "")
  elseif family_code == "16" or family_code == "18" or family_code == "21" then
    return family_code .. (i_series and "i" or "") .. "-" .. machine_letter .. (model_letter or "")
  elseif family_code == "15" then
    local base = legacy_15_layout and "15" or "15i"
    return (#machine_letter > 0) and (base .. "-" .. machine_letter) or base
  elseif family_code == "PD" then
    return "Power Mate i-D"
  elseif family_code == "PH" then
    return "Power Mate i-H"
  elseif family_code == "PM" then
    return "Power Motion i"
  end
end

local function read_control_profile(sock, host, port)
  local r, err = request_query(sock, QUERY_MACHINE_PROFILE)
  if not r then return "error: " .. tostring(err) end
  if r.rc ~= 0 then return "failed: " .. result_label(r.rc) end
  if #r.data < 18 then return ("short response (%dB)"):format(#r.data) end

  local data         = r.data
  local family_code  = trim(data:sub(5, 6))
  local machine_code = trim(data:sub(7, 8))
  local series       = trim(data:sub(9, 12))
  local version      = trim(data:sub(13, 16))
  local axes_str     = trim(data:sub(17, 18))

  local profile_bits, _, legacy_15_layout = detect_profile_layout(data, family_code)
  local has_loader, i_series, has_compound, has_xferline, model_letter
  if not legacy_15_layout then
    has_loader   = (profile_bits & 0x0001) ~= 0
    i_series     = (profile_bits & 0x0002) ~= 0
    has_compound = (profile_bits & 0x0008) ~= 0
    has_xferline = (profile_bits & 0x0010) ~= 0
    model_letter = MODEL_SUFFIX_LABELS[(profile_bits >> 8) & 0xFF]
  end

  local model = friendly_model(family_code, machine_code, i_series, model_letter, legacy_15_layout)
  local caps = {}
  if i_series     then caps[#caps + 1] = "i-Series"           end
  if has_loader   then caps[#caps + 1] = "loader control"     end
  if has_compound then caps[#caps + 1] = "compound machining" end
  if has_xferline then caps[#caps + 1] = "transfer line"      end

  local t = stdnse.output_table()
  if model then t.model = model end
  t.control = CONTROL_FAMILY_LABELS[family_code] or family_code
  t.machine = MACHINE_KIND_LABELS[machine_code]  or machine_code
  t.series   = series
  t.version  = version
  t.axes     = axes_str
  if #caps > 0 then t.capabilities = table.concat(caps, ", ") end

  if model then port.version.version = model end
  port.version.extrainfo = ("series %s, version %s"):format(series, version)
  nmap.set_port_version(host, port, "hardmatched")
  return t
end

local function pack_status_bundle()
  local function subreq(query_id)
    return string.pack(">I2I2I2I2", 28, 0x0001, 0x0001, query_id)
            .. string.rep("\0", 20)
  end

  return string.pack(">I2", 3)
          .. subreq(QUERY_RUNTIME_STATE)
          .. subreq(QUERY_STATE_AUX_1)
          .. subreq(QUERY_STATE_AUX_2)
end

local function decode_status(data)
  if #data >= 18 then
    local _channel_marker, _timer_mode, path_mode, run_mode, motion_mode,
          aux_signal, emergency_flag, alarm_flag, edit_state =
        string.unpack(">I2I2I2I2I2I2I2I2I2", data)
    return path_mode, run_mode, motion_mode, aux_signal,
           emergency_flag, alarm_flag, edit_state
  elseif #data >= 14 then
    return string.unpack(">I2I2I2I2I2I2I2", data)
  end
end

local function read_status(sock)
  local r, err = call(sock, pack_status_bundle())
  if not r then return "error: " .. tostring(err) end
  if r.subreq_count < 1 then return "parse error" end
  if r.rc ~= 0 then return "failed: " .. result_label(r.rc) end

  local path_mode, run_mode, motion_mode, aux_signal, emergency_flag,
        alarm_flag, edit_state = decode_status(r.data)
  if not path_mode then return ("parse error (short status data %dB)"):format(#r.data) end

  local t = stdnse.output_table()
  t.mode       = label_value(PATH_MODE_LABELS, path_mode)
  t.run_state  = label_value(RUN_LABELS, run_mode)
  t.motion     = label_value(MOTION_LABELS, motion_mode)
  t.aux_signal = label_value(AUX_SIGNAL_LABELS, aux_signal)
  t.alarm      = (alarm_flag ~= 0) and "ALARM"          or "no alarm"
  t.emergency  = (emergency_flag ~= 0) and "EMERGENCY STOP" or "ok"
  t.edit       = label_value(EDIT_LABELS, edit_state)
  return t
end

local function decode_alarm_bits(bitmap)
  local bits = {}
  for i = 0, 31 do
    if (bitmap >> i) & 1 == 1 then
      bits[#bits + 1] = ALERT_FLAG_LABELS[i] or ("bit" .. i)
    end
  end
  return (#bits > 0) and table.concat(bits, "; ") or "(no alarms)"
end

local function read_alarm_messages(sock, max_alarms)
  local r = request_query(sock, QUERY_ALARM_TEXT, { -1, max_alarms, 2, 64, 0 })
  if not r then return nil end
  if r.rc ~= 0 then return "alarm text query failed: " .. result_label(r.rc) end
  if #r.data < 80 then return nil end

  local messages = {}
  local slot_size = 80
  local slots = math.min(math.floor(#r.data / slot_size), max_alarms)
  for i = 0, slots - 1 do
    local off = i * slot_size + 1
    local alarm_number = string.unpack(">I4", r.data, off)
    local alarm_group  = string.unpack(">I2", r.data, off + 6)
    local axis    = string.unpack(">I2", r.data, off + 10)
    local msg_len = math.min(string.unpack(">I2", r.data, off + 14), 64)
    if alarm_number == 0 and msg_len == 0 then break end

    local msg_start = off + 16
    local msg = clean_text(r.data:sub(msg_start, msg_start + msg_len - 1))
    messages[#messages + 1] = ("[%d] alarm=%-5d group=%d axis=%d  %s"):format(
                                i, alarm_number, alarm_group, axis, msg)
  end

  return (#messages > 0) and messages or nil
end

local function read_alarms(sock, max_alarms)
  local t = stdnse.output_table()

  local r, err = request_query(sock, QUERY_ALARM_FLAGS)
  if not r then
    t.bits_set = "alarm flag query error: " .. tostring(err)
  elseif r.rc ~= 0 then
    t.bits_set = "alarm flag query failed: " .. result_label(r.rc)
  elseif #r.data >= 4 then
    t.bits_set = decode_alarm_bits(string.unpack(">I4", r.data, 1))
  else
    t.bits_set = ("alarm flag query short response (%dB)"):format(#r.data)
  end

  local messages = read_alarm_messages(sock, max_alarms)
  if messages then t.messages = messages end
  return t
end

local function read_active_program(sock)
  local t = stdnse.output_table()

  local p = request_query(sock, QUERY_ACTIVE_PROGRAMS)
  if p and p.rc == 0 and #p.data >= 8 then
    t.running_O = format_o_number(string.unpack(">I4", p.data, 1))
    t.main_O    = format_o_number(string.unpack(">I4", p.data, 5))
  end

  local seq = request_query(sock, QUERY_SEQUENCE_NUMBER)
  if seq and seq.rc == 0 and #seq.data >= 4 then
    t.sequence = string.unpack(">I4", seq.data, 1)
  end

  local name = request_query(sock, QUERY_ACTIVE_NAME)
  if name and name.rc == 0 and #name.data >= 40 then
    local o_num = string.unpack(">I4", name.data, 1)
    local program_name = clean_text(name.data:sub(5, 40))
    if o_num > 0 then t.exe_o_num = format_o_number(o_num) end
    if #program_name > 0 then t.program_name = program_name end
  end

  return t
end

local function decode_program_batch(data)
  local batch = {}
  local slot_size = 72
  local slots = math.floor(#data / slot_size)

  for i = 0, slots - 1 do
    local base = i * slot_size + 1
    local o_num = string.unpack(">I4", data, base)
    if o_num == 0 then break end

    local comment = data:sub(base + 8, base + 8 + 63)
    batch[#batch + 1] = {
      o_num = o_num,
      size = string.unpack(">I4", data, base + 4),
      comment = clean_text(comment),
    }
  end

  return batch
end

local function read_programs(sock, max_progs)
  if max_progs == 0 then return "programs", "(skipped by maxprogs=0)" end

  local programs = {}
  local top = 0
  local batch_size = 16
  local truncated = false

  while #programs < max_progs do
    local r = request_query(sock, QUERY_PROGRAM_CATALOG, { top, batch_size, 2, 0, 0 })
    if not r or r.rc ~= 0 then break end

    local batch = decode_program_batch(r.data)
    if #batch == 0 then break end

    local last_o = 0
    for _, entry in ipairs(batch) do
      if #programs >= max_progs then truncated = true; break end
      programs[#programs + 1] = entry
      if entry.o_num > last_o then last_o = entry.o_num end
    end

    if #programs >= max_progs then
      if #batch >= batch_size then truncated = true end
      break
    end
    if last_o == 0 or last_o + 1 <= top then break end

    top = last_o + 1
    if #batch < batch_size then break end
  end

  if #programs == 0 then return "programs", "(none enumerated)" end

  local lines = {}
  for _, entry in ipairs(programs) do
    lines[#lines + 1] = ("%s  %6d B  %s"):format(
                          format_o_number(entry.o_num), entry.size or 0, entry.comment or "")
  end

  local suffix = truncated and " listed, capped by maxprogs" or " in CNC memory"
  return ("programs (%d%s)"):format(#programs, suffix), lines
end

-- ---------------------------------------------------------------------------
-- portrule + action
-- ---------------------------------------------------------------------------

portrule = shortport.port_or_service(8193, "focas", "tcp")

action = function(host, port)
  local args = stdnse.get_script_args
  local timeout_s = stdnse.parse_timespec(args(SCRIPT_NAME .. ".timeout") or "5s") or 5
  local timeout_ms = clamp_int(timeout_s * 1000, 5000, 100, 600000)
  local max_progs = clamp_int(args(SCRIPT_NAME .. ".maxprogs"), 100, 0, 10000)
  local max_alarms = clamp_int(args(SCRIPT_NAME .. ".maxalarms"), 10, 1, 64)

  local out = stdnse.output_table()
  local sock1, err1 = open_control_channel(host, port, 1, timeout_ms)
  if not sock1 then out.error = "handshake conn#1: " .. tostring(err1); return out end

  local sock2, err2 = open_control_channel(host, port, 2, timeout_ms)
  if not sock2 then
    close_control_channel(sock1)
    out.error = "handshake conn#2: " .. tostring(err2)
    return out
  end

  port.version = port.version or {}
  port.version.name = "focas"
  port.version.product = "Fanuc FOCAS 2 (Ethernet)"
  nmap.set_port_version(host, port, "hardmatched")

  local ok, perr = pcall(function()
    out.system = read_control_profile(sock2, host, port)
    out.status = read_status(sock2)
    out.alarms = read_alarms(sock2, max_alarms)
    out.active_program = read_active_program(sock2)

    local programs_key, programs_value = read_programs(sock2, max_progs)
    out[programs_key] = programs_value
  end)

  close_control_channel(sock2)
  close_control_channel(sock1)

  if not ok then
    out.error = "internal error: " .. tostring(perr)
  end
  return out
end
