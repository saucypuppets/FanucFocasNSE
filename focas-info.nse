local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates a Fanuc CNC controller exposing FOCAS 2 over Ethernet (TCP/8193).

The script performs read-only FOCAS queries for system information, machine
status, active program details, and the CNC program directory. It never
sends write or control requests.
]]

---
-- @usage
-- nmap -p 8193 --script focas-info <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8193/tcp open  focas
-- | focas-info:
-- |   System:
-- |     Model:        0i-MD
-- |     Control:      0i
-- |     Machine:      Milling
-- |     Series:       D4F1
-- |     Version:      37.0
-- |     Axes:         03
-- |     Capabilities: i-Series
-- |   Status:
-- |     Mode:       MDI
-- |     Run State:  STOP
-- |     Motion:     none
-- |     Aux Signal: none
-- |     Alarm:      ALARM
-- |     Emergency:  EMERGENCY STOP
-- |     Edit:       not editing
-- |   Active Program:
-- |     Running O-number:   O5112
-- |     Main O-number:      O5112
-- |     Sequence:           0
-- |     Executing O-number: O5112
-- |     Program Name:       O5112
-- |   Programs:
-- |     Count:   16
-- |     Source:  CNC memory
-- |     Entries:
-- |       O0090     500 B  ()
-- |       O0249    1500 B  (SHAVE 5MM 73.1)
-- |       O0545     500 B  ()
-- |       O0671     500 B  ()
-- |       O0703    1000 B  ()
-- |       O1993    3500 B  (OPEN BORE 87.1 CHAMFER)
-- |_      O1994    4500 B  (OPEN BORE 130.2 CHAMFER)
--
-- @xmloutput
-- <table key="System">
--   <elem key="Model">0i-MD</elem>
--   <elem key="Control">0i</elem>
--   <elem key="Machine">Milling</elem>
--   <elem key="Series">D4F1</elem>
--   <elem key="Version">37.0</elem>
--   <elem key="Axes">03</elem>
--   <elem key="Capabilities">i-Series</elem>
-- </table>
-- <table key="Status">
--   <elem key="Mode">MDI</elem>
--   <elem key="Run State">STOP</elem>
--   <elem key="Motion">none</elem>
--   <elem key="Aux Signal">none</elem>
--   <elem key="Alarm">ALARM</elem>
--   <elem key="Emergency">EMERGENCY STOP</elem>
--   <elem key="Edit">not editing</elem>
-- </table>
-- <table key="Active Program">
--   <elem key="Running O-number">O5112</elem>
--   <elem key="Main O-number">O5112</elem>
--   <elem key="Sequence">0</elem>
--   <elem key="Executing O-number">O5112</elem>
--   <elem key="Program Name">O5112</elem>
-- </table>
-- <table key="Programs">
--   <elem key="Count">16</elem>
--   <elem key="Source">CNC memory</elem>
--   <table key="Entries">
--     <elem>O0090       500 B  ()</elem>
--     <elem>O0249      1500 B  (SHAVE 5MM 73.1)</elem>
--   </table>
-- </table>

author = "saucypuppets"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

-- ---------------------------------------------------------------------------
-- Protocol frame markers (all multi-byte fields are big-endian)
-- ---------------------------------------------------------------------------

local FRAME_MARKER = "\xA0\xA0\xA0\xA0"

local FRAME_LINK_START = 0x0101
local FRAME_LINK_READY = 0x0102
local FRAME_LINK_STOP  = 0x0201
local FRAME_READ_BLOCK = 0x2101
local FRAME_READ_REPLY = 0x2102

local FRAME_FLAGS_REQUEST = 0x0001
local FRAME_FLAGS_REPLY   = 0x0004

-- FOCAS envelope (inner) layout
local ENVELOPE_SUBREQ_COUNT = 1   -- single-query envelope
local ENVELOPE_INNER_LEN    = 28  -- fixed body size
local ENVELOPE_FLAG         = 1   -- flag1 and flag2

local QUERY_MACHINE_PROFILE  = 0x0018
local QUERY_RUNTIME_STATE    = 0x0019
local QUERY_ACTIVE_PROGRAMS  = 0x001C
local QUERY_SEQUENCE_NUMBER  = 0x001D
local QUERY_ACTIVE_NAME      = 0x00CF
local QUERY_PROGRAM_CATALOG  = 0x0006

-- FOCAS Data Window return codes (see ERRCODE.HTM in the FOCAS Library docs).
-- HSSB-only codes (-3, -4, -5, -9, -10, -11, -15) are omitted -- they cannot
-- occur over Ethernet.
local RESULT_TEXT = {
  [   0] = "ok",
  [   1] = "function not available",
  [   2] = "bad length",
  [   3] = "bad number",
  [   4] = "bad attribute",
  [   5] = "bad data",
  [   6] = "option unavailable",
  [   7] = "write protected",
  [   8] = "memory overflow",
  [   9] = "bad parameter",
  [  10] = "buffer empty or full",
  [  11] = "bad path number",
  [  12] = "bad CNC mode",
  [  13] = "execution rejected",
  [  14] = "data server error",
  [  15] = "blocked by alarm",
  [  16] = "CNC stopped or emergency",
  [  17] = "data protected",
  [  -1] = "busy",
  [  -2] = "reset or stop",
  [  -6] = "abnormal library state",
  [  -7] = "version mismatch",
  [  -8] = "bad handle",
  [ -16] = "socket error",
  [ -17] = "protocol error",
}

local function result_label(code)
  return RESULT_TEXT[code] or ("rc=" .. tostring(code))
end

-- Modern controllers (Series 16/18/21, 16i/18i/21i, 0i, 30i/31i/32i,
-- Power Mate i): combined automatic/manual mode in single `aut` field.
local PATH_MODE_LABELS_MODERN = {
  [0]="MDI", [1]="MEM", [2]="(none)", [3]="EDIT", [4]="HND",
  [5]="JOG", [6]="T/JOG", [7]="T/HND", [8]="INC", [9]="REF", [10]="RMT",
}
-- Series 15/15i: `aut` is automatic-mode-only; manual mode is in a separate
-- field that this script doesn't surface.
local PATH_MODE_LABELS_SERIES15 = {
  [0]="(none)", [1]="MDI", [2]="TAPE/DNC", [3]="MEM", [4]="EDIT", [5]="TeachIN",
}

-- Modern run/auto-operation state. Series 15 uses different codes (see below).
local RUN_LABELS_MODERN = {
  [0]="(reset)", [1]="STOP", [2]="HOLD", [3]="START", [4]="MSTR",
}
-- Series 15/15i run state -- offset by 1 from modern, plus higher codes for
-- restart/search/HPCC states modern controllers report differently.
local RUN_LABELS_SERIES15 = {
  [0]="STOP", [1]="HOLD", [2]="START", [3]="MSTR (jog mdi)",
  [4]="ReSTaRt", [5]="PRSR (program restart)", [6]="NSRC (seq search)",
  [7]="ReSTaRt (blinking)", [8]="ReSET", [13]="HPCC",
}

local MOTION_LABELS = {
  [0]="none", [1]="motion", [2]="dwell", [3]="wait (TT multi-path)",
}
local AUX_SIGNAL_LABELS = {
  [0]="none", [1]="FIN",
}

-- Modern edit/other state (M-series codes; T-series varies at 7-15 and 26+).
local EDIT_LABELS_MODERN = {
  [0]="not editing", [1]="EDIT", [2]="SEARCH", [3]="OUTPUT",
  [4]="INPUT", [5]="COMPARE", [6]="LABEL SKIP", [7]="RESTART",
  [8]="HPCC", [9]="PTRR", [10]="RVRS", [11]="RTRY", [12]="RVED",
  [13]="HANDLE", [14]="OFFSET", [15]="WORK OFFSET", [16]="AICC",
  [17]="MEM-CHK", [18]="CUSTOM BOARD", [19]="SAVE", [20]="AI NANO",
  [21]="AI APC", [22]="MBL APC", [23]="AICC 2", [24]="AI HPCC",
  [25]="5-AXIS",
}
-- Series 15/15i edit state: completely different beyond code 2.
local EDIT_LABELS_SERIES15 = {
  [0]="not editing", [1]="EDIT", [2]="SEARCH", [3]="VERIFY",
  [4]="CONDENSE", [5]="READ", [6]="PUNCH",
}

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
-- Profile bits 8-15 hold the model letter. Value 5 (E) is unused.
local MODEL_SUFFIX_LABELS = { [1]="A", [2]="B", [3]="C", [4]="D", [6]="F" }

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

-- ---------------------------------------------------------------------------
-- Frame I/O
-- ---------------------------------------------------------------------------

-- sock:receive_buf delim callback. FOCAS frames are length-prefixed: 10-byte
-- header, uint16 payload length at bytes 9-10. We ignore `init` and parse
-- from position 1 -- a re-call after a partial read shouldn't shift the
-- offset.
local function focas_frame_complete(buf, init)
  if #buf < 10 then return nil end
  local payload_len = string.unpack(">I2", buf, 9)
  local total = 10 + payload_len
  if #buf < total then return nil end
  return 1, total
end

---
-- Reads one complete FOCAS frame from the socket. Uses receive_buf with
-- focas_frame_complete as the delimiter so length-prefixed framing works
-- across TCP read boundaries.
--
-- @param sock NSE socket connected to the FOCAS controller.
-- @return Frame table {flags, opcode, payload} on success; nil and an
--         error string on failure.
local function recv_frame(sock)
  local status, frame = sock:receive_buf(focas_frame_complete, true)
  if not status then return nil, "recv: " .. tostring(frame) end
  if frame:sub(1, 4) ~= FRAME_MARKER then
    return nil, ("bad magic: %s"):format(stdnse.tohex(frame:sub(1, 4)))
  end
  local flags, opcode, plen = string.unpack(">I2I2I2", frame, 5)
  local payload = (plen > 0) and frame:sub(11, 10 + plen) or ""
  stdnse.debug2("recv frame: flags=0x%04x opcode=0x%04x payload=%dB", flags, opcode, plen)
  return { flags = flags, opcode = opcode, payload = payload }
end

---
-- Wraps a payload in a FOCAS outer frame: 4-byte marker, 2-byte flags,
-- 2-byte opcode, 2-byte payload length, then the payload. Outbound frames
-- always use FRAME_FLAGS_REQUEST.
--
-- @param opcode Frame opcode (one of the FRAME_LINK_* / FRAME_READ_*
--               constants).
-- @param payload Pre-built payload bytes (may be empty).
-- @return Bytes ready to send on the wire.
local function pack_frame(opcode, payload)
  return FRAME_MARKER .. string.pack(">I2I2I2",
                                     FRAME_FLAGS_REQUEST, opcode, #payload) .. payload
end

-- ---------------------------------------------------------------------------
-- Session setup opens two connections; only the second carries data.
-- ---------------------------------------------------------------------------

---
-- Opens a TCP connection to the FOCAS controller and completes the LINK_START
-- handshake. FOCAS requires two channels per client; the script opens both
-- (ordinal 1 and 2) but only the second carries data.
--
-- @param host Nmap host object.
-- @param port Nmap port object.
-- @param ordinal Channel number (1 or 2).
-- @param timeout_ms Socket timeout in milliseconds.
-- @return Connected socket on success; nil and an error string on failure.
local function open_control_channel(host, port, ordinal, timeout_ms)
  stdnse.debug1("opening control channel ordinal=%d (timeout=%dms)", ordinal, timeout_ms)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout_ms)
  local ok, err = sock:connect(host, port, "tcp")
  if not ok then return nil, "connect failed: " .. tostring(err) end

  local hs = pack_frame(FRAME_LINK_START, string.pack(">I2", ordinal))
  local sent, serr = sock:send(hs)
  if not sent then sock:close(); return nil, "handshake send: " .. tostring(serr) end
  local resp, rerr = recv_frame(sock)
  if not resp then sock:close(); return nil, "handshake recv: " .. tostring(rerr) end
  if resp.flags ~= FRAME_FLAGS_REPLY or resp.opcode ~= FRAME_LINK_READY then
    sock:close()
    return nil, ("unexpected handshake reply: flags=0x%04x opcode=0x%04x"):format(
                  resp.flags, resp.opcode)
  end
  stdnse.debug1("control channel ordinal=%d ready", ordinal)
  return sock
end

---
-- Sends a LINK_STOP, attempts to read the reply, then closes the socket.
-- Safe to call with a nil sock (no-op). Send and recv errors are ignored
-- because the peer may already be gone.
--
-- @param sock Socket previously returned by open_control_channel, or nil.
local function close_control_channel(sock)
  if not sock then return end
  stdnse.debug1("closing control channel")
  -- Attempt the polite LINK_STOP exchange; ignore failures (sock:send and
  -- recv_frame return nil, err rather than raising, so this is safe).
  sock:send(pack_frame(FRAME_LINK_STOP, ""))
  recv_frame(sock)
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

---
-- Builds a single-subrequest FOCAS envelope for a read query. Missing args
-- default to 0; the caller's table is not mutated.
--
-- @param query_id FOCAS query identifier (one of the QUERY_* constants).
-- @param args Optional table of up to 5 int32 arguments.
-- @return 30-byte envelope ready to wrap in a frame.
local function pack_envelope(query_id, args)
  args = args or {}
  return string.pack(">I2I2I2I2I2i4i4i4i4i4",
                     ENVELOPE_SUBREQ_COUNT, ENVELOPE_INNER_LEN,
                     ENVELOPE_FLAG, ENVELOPE_FLAG, query_id,
                     args[1] or 0, args[2] or 0, args[3] or 0,
                     args[4] or 0, args[5] or 0)
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
---
-- Parses the first sub-response of a FOCAS read reply payload. The script
-- only ever sends single-query envelopes, so the first sub-response is
-- the only one that matters.
--
-- @param payload Payload bytes from a FRAME_READ_REPLY frame.
-- @return Parsed response table on success; nil and an error string if
--         the payload is too short or self-inconsistent.
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

---
-- Sends a FRAME_READ_BLOCK request carrying an already-packed envelope
-- and returns the parsed FRAME_READ_REPLY response. The single round-trip
-- primitive used by every higher-level read in the script.
--
-- @param sock Connected FOCAS data channel.
-- @param request_payload Pre-built envelope bytes.
-- @return Parsed response table on success; nil and an error string on
--         failure.
local function send_request(sock, request_payload)
  local ok, err = sock:send(pack_frame(FRAME_READ_BLOCK, request_payload))
  if not ok then return nil, "send: " .. tostring(err) end
  local resp, rerr = recv_frame(sock)
  if not resp then return nil, "recv: " .. tostring(rerr) end
  if resp.flags ~= FRAME_FLAGS_REPLY or resp.opcode ~= FRAME_READ_REPLY then
    return nil, ("bad reply: flags=0x%04x opcode=0x%04x"):format(resp.flags, resp.opcode)
  end
  local parsed, perr = parse_response(resp.payload)
  if parsed then
    stdnse.debug2("reply: query_id=0x%04x rc=%d data_len=%d",
                  parsed.query_id, parsed.rc, parsed.data_len)
  end
  return parsed, perr
end

---
-- Convenience wrapper: packs an envelope for the given query id and args,
-- sends it as a read-block request, and returns the parsed response.
--
-- @param sock Connected FOCAS data channel.
-- @param query_id FOCAS query identifier.
-- @param args Optional table of up to 5 int32 query arguments.
-- @return Same as send_request: parsed response table or nil, err.
local function request_query(sock, query_id, args)
  stdnse.debug2("query: id=0x%04x", query_id)
  return send_request(sock, pack_envelope(query_id, args))
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

---
-- Distinguishes Series 15 non-i controllers from Series 15i and newer.
-- Series 15 stores max_axis as 2 ASCII characters at offset 2-3; newer
-- variants put a binary uint16 there. ASCII bytes are detected by the
-- value being large (>256) or both bytes being zero (the "10 axes" case).
--
-- @param data ODBSYS response data bytes.
-- @param family_code Trimmed cnc_type string (e.g. "0", "15", "30").
-- @return profile_bits, axis_word, legacy_15_layout flag.
local function detect_profile_layout(data, family_code)
  local profile_bits = string.unpack(">I2", data, 1)
  local axis_word = string.unpack(">I2", data, 3)

  -- Series 15 non-i stores the axis field as ASCII, not a binary short.
  local legacy_15_layout = (family_code == "15" and (axis_word == 0 or axis_word > 256))
  return profile_bits, axis_word, legacy_15_layout
end

---
-- Builds a human-readable model name from the controller's family code,
-- machine type, i-series flag, model letter (A/B/C/D/F), and the
-- legacy-15 layout flag. Handles the eight documented family codes.
--
-- @param family_code Trimmed cnc_type ("0", "15", "16", "18", "21", "30",
--                    "31", "32", "35", "PD", "PH", "PM").
-- @param machine_code Trimmed mt_type ("M", "T", "MM", "TT", "MT", etc.).
-- @param i_series Boolean; true if profile bit 1 indicates i-Series.
-- @param model_letter "A".."F" (no "E") or nil if not supported.
-- @param legacy_15_layout True for Series 15 non-i (different ODBSYS layout).
-- @return Model name string, or nil for unknown families.
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

---
-- Queries the controller for system information (family, machine type,
-- series, version, axes, capability bits) and populates a sub-table for
-- Nmap output. Also updates port.version.version and port.version.extrainfo
-- on the supplied port object when a model can be identified.
--
-- @param sock Connected FOCAS data channel.
-- @param host Nmap host object (passed through to port.version updates).
-- @param port Nmap port object whose version fields are updated in place.
-- @return Output sub-table on success, or an error string if the query
--         failed or the response was malformed.
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
  if model then t["Model"] = model end
  t["Control"] = CONTROL_FAMILY_LABELS[family_code] or family_code
  t["Machine"] = MACHINE_KIND_LABELS[machine_code]  or machine_code
  t["Series"]  = series
  t["Version"] = version
  t["Axes"]    = axes_str
  if #caps > 0 then t["Capabilities"] = table.concat(caps, ", ") end

  if model then port.version.version = model end
  port.version.extrainfo = ("series %s, version %s"):format(series, version)
  return t
end

---
-- Unpacks the runtime status fields (path mode, run state, motion, aux
-- signal, emergency, alarm, edit) from a cnc_statinfo response. Handles
-- both the 28-byte Series 15 layout and the 14-/18-byte modern layout.
--
-- @param data ODBST response data bytes.
-- @return Seven uint16 values (path_mode, run_mode, motion_mode,
--         aux_signal, emergency_flag, alarm_flag, edit_state), or nothing
--         if the data is too short to decode.
local function decode_status(data)
  if #data >= 28 then
    -- Series 15 / 15i layout (28-byte ODBST): different field order with
    -- manual + edit interleaved early. Struct (from cnc_statinfo.xml):
    --   dummy[2] + aut + manual + run + edit + motion + mstb + emergency +
    --   write + labelskip + alarm + warning + battery
    -- We map: aut->path_mode, run->run_mode, motion->motion_mode,
    --         mstb->aux_signal, emergency->emergency_flag,
    --         alarm->alarm_flag, edit->edit_state. The other fields
    --         (manual, write, labelskip, warning, battery) are dropped.
    local _d1, _d2, aut, _manual, run, edit, motion, mstb, emergency,
          _write, _labelskip, alarm, _warning, _battery =
        string.unpack(">I2I2I2I2I2I2I2I2I2I2I2I2I2I2", data)
    return aut, run, motion, mstb, emergency, alarm, edit
  elseif #data >= 14 then
    -- Modern ODBST (18B, hdck+tmmode prefix) or 16i/18i-W ODBST (18B,
    -- dummy[2] prefix): both put the 7 fields we want in the trailing
    -- 14 bytes, so slicing the tail handles either layout with one unpack.
    local path_mode, run_mode, motion_mode, aux_signal,
          emergency_flag, alarm_flag, edit_state =
        string.unpack(">I2I2I2I2I2I2I2", data:sub(-14))
    return path_mode, run_mode, motion_mode, aux_signal,
           emergency_flag, alarm_flag, edit_state
  end
end

---
-- Queries the controller's runtime status (cnc_statinfo) and translates the
-- raw codes into human-readable mode / state / motion / signal / alarm /
-- emergency / edit labels. Picks Modern or Series 15 label tables based on
-- the response size.
--
-- @param sock Connected FOCAS data channel.
-- @return Output sub-table on success, or an error string on protocol or
--         parse failure.
local function read_status(sock)
  local r, err = request_query(sock, QUERY_RUNTIME_STATE)
  if not r then return "error: " .. tostring(err) end
  if r.rc ~= 0 then return "failed: " .. result_label(r.rc) end

  local path_mode, run_mode, motion_mode, aux_signal, emergency_flag,
        alarm_flag, edit_state = decode_status(r.data)
  if not path_mode then return ("parse error (short status data %dB)"):format(#r.data) end

  -- 28-byte response is the Series 15/15i ODBST layout; everything else is
  -- modern or 16i/18i-W. Label codings differ between the two families, so
  -- pick the matching tables.
  local is_series15 = (#r.data >= 28)
  local path_labels = is_series15 and PATH_MODE_LABELS_SERIES15 or PATH_MODE_LABELS_MODERN
  local run_labels  = is_series15 and RUN_LABELS_SERIES15       or RUN_LABELS_MODERN
  local edit_labels = is_series15 and EDIT_LABELS_SERIES15      or EDIT_LABELS_MODERN

  local t = stdnse.output_table()
  t["Mode"]       = label_value(path_labels, path_mode)
  t["Run State"]  = label_value(run_labels, run_mode)
  t["Motion"]     = label_value(MOTION_LABELS, motion_mode)
  t["Aux Signal"] = label_value(AUX_SIGNAL_LABELS, aux_signal)
  t["Alarm"]      = (alarm_flag ~= 0)     and "ALARM"          or "no alarm"
  t["Emergency"]  = (emergency_flag ~= 0) and "EMERGENCY STOP" or "ok"
  t["Edit"]       = label_value(edit_labels, edit_state)
  return t
end

---
-- Reads the controller's current program state via three separate FOCAS
-- queries (cnc_rdprgnum, cnc_rdseqnum, cnc_exeprgname). Fields are
-- pre-populated with FOCAS "no program / no sequence" sentinels (O0000 / 0
-- / empty string) so the output schema is stable even when a sub-query
-- fails or returns no active program.
--
-- @param sock Connected FOCAS data channel.
-- @return Output sub-table; always returned, never an error string.
local function read_active_program(sock)
  local t = stdnse.output_table()
  t["Running O-number"]   = format_o_number(0)
  t["Main O-number"]      = format_o_number(0)
  t["Sequence"]           = 0
  t["Executing O-number"] = format_o_number(0)
  t["Program Name"]       = ""

  local p = request_query(sock, QUERY_ACTIVE_PROGRAMS)
  if p and p.rc == 0 and #p.data >= 8 then
    t["Running O-number"] = format_o_number(string.unpack(">I4", p.data, 1))
    t["Main O-number"]    = format_o_number(string.unpack(">I4", p.data, 5))
  end

  local seq = request_query(sock, QUERY_SEQUENCE_NUMBER)
  if seq and seq.rc == 0 and #seq.data >= 4 then
    t["Sequence"] = string.unpack(">I4", seq.data, 1)
  end

  local name = request_query(sock, QUERY_ACTIVE_NAME)
  if name and name.rc == 0 and #name.data >= 40 then
    t["Executing O-number"] = format_o_number(string.unpack(">I4", name.data, 1))
    t["Program Name"]       = clean_text(name.data:sub(5, 40))
  end

  return t
end

---
-- Decodes one batch of program-catalog entries. Each entry is a 72-byte
-- slot: 4-byte O-number, 4-byte size, then a 64-byte comment field.
-- Stops at the first slot whose O-number is zero.
--
-- @param data Catalog response data bytes.
-- @return List of {o_num, size, comment} tables (possibly empty).
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

---
-- Walks the controller's program catalog in batches of 16 entries, stopping
-- when the controller signals end-of-catalog (empty batch, partial batch,
-- or no progress on the highest O-number returned).
--
-- @param sock Connected FOCAS data channel.
-- @return Output sub-table with Count, Source, and Entries (list of
--         "Oxxxx  N B  comment" lines).
local function read_programs(sock)
  local t = stdnse.output_table()
  t["Count"]   = 0
  t["Source"]  = "CNC memory"
  t["Entries"] = {}

  local programs = {}
  local top = 0
  local batch_size = 16

  while true do
    local r = request_query(sock, QUERY_PROGRAM_CATALOG, { top, batch_size, 2, 0, 0 })
    if not r or r.rc ~= 0 then break end

    local batch = decode_program_batch(r.data)
    if #batch == 0 then break end

    local last_o = 0
    for _, entry in ipairs(batch) do
      programs[#programs + 1] = entry
      if entry.o_num > last_o then last_o = entry.o_num end
    end

    if last_o == 0 or last_o + 1 <= top then break end

    top = last_o + 1
    if #batch < batch_size then break end
  end

  t["Count"] = #programs
  for _, entry in ipairs(programs) do
    t["Entries"][#t["Entries"] + 1] = ("%s  %6d B  %s"):format(
                          format_o_number(entry.o_num), entry.size or 0, entry.comment or "")
  end

  stdnse.debug1("enumerated %d programs", t["Count"])
  return t
end

-- ---------------------------------------------------------------------------
-- portrule + action
-- ---------------------------------------------------------------------------

portrule = shortport.version_port_or_service(8193, "focas", "tcp")

---
-- Script entry point. Opens two FOCAS control channels, identifies the port
-- as FOCAS, then runs the four read functions and returns their combined
-- output. Returns nil if the handshake fails (not a FOCAS service).
--
-- @param host Host that was scanned via nmap.
-- @param port Port that was scanned via nmap.
-- @return Output table on success, nil if the controller does not respond
--         as a FOCAS endpoint.
action = function(host, port)
  local timeout_ms = stdnse.get_timeout(host, 8000, 1000)

  stdnse.debug1("starting FOCAS enumeration against %s:%d (timeout=%dms)",
                host.ip, port.number, timeout_ms)

  local sock1, err1 = open_control_channel(host, port, 1, timeout_ms)
  if not sock1 then
    stdnse.debug1("handshake conn#1: %s", tostring(err1))
    return nil
  end

  local sock2, err2 = open_control_channel(host, port, 2, timeout_ms)
  if not sock2 then
    stdnse.debug1("handshake conn#2: %s", tostring(err2))
    close_control_channel(sock1)
    return nil
  end

  port.state = "open"
  port.version.name = "focas"
  port.version.name_confidence = 10
  port.version.product = "Fanuc FOCAS 2 (Ethernet)"
  port.version.devicetype = "specialized"

  local out = stdnse.output_table()
  out["System"]         = read_control_profile(sock2, host, port)
  out["Status"]         = read_status(sock2)
  out["Active Program"] = read_active_program(sock2)
  out["Programs"]       = read_programs(sock2)

  nmap.set_port_version(host, port, "hardmatched")
  nmap.set_port_state(host, port, "open")
  close_control_channel(sock2)
  close_control_channel(sock1)
  stdnse.debug1("FOCAS enumeration complete")
  return out
end
