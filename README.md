# FanucFocasNSE
`fanuc-focas-enum.nse` enumerates a Fanuc CNC controller exposing FOCAS 2
over Ethernet, normally on TCP/8193.

The script performs read-only queries and reports:

- Session channels used for controller communication.
- Controller model, family, version, and axis information.
- Run, mode, alarm, emergency, and edit status.
- Current alarm flags and active alarm messages.
- Active program details.
- Program directory entries.

The implementation is intentionally narrow: it focuses on common Ethernet
FOCAS inventory and status data, and avoids write, control, upload, download,
and delete operations. Some payload layouts vary by controller family, so
the script decodes status fields defensively.

Useful arguments:

- `fanuc-focas-enum.timeout`: socket timeout, default `5s`.
- `fanuc-focas-enum.maxprogs`: maximum programs to list, default `100`.
- `fanuc-focas-enum.maxalarms`: maximum alarm messages to read, default `10`.
