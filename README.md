# FanucFocasNSE
`fanuc-focas-enum.nse` enumerates a Fanuc CNC controller exposing FOCAS over Ethernet, normally on TCP/8193.

The script performs read-only queries with raw packets:

- Controller model, family, version, and axis information.
- Run, mode, alarm, emergency, and edit status.
- Current alarm flags and active alarm messages.
- Active program details.
- Lists all programs accesible in CNC_MEM

Developed against a bare-bones 0i-MD control. Needs validation against additional families of CNC control, Data Server, and FAST ethernet cards. 

Useful arguments:

- `fanuc-focas-enum.timeout`: socket timeout, default `5s`.
- `fanuc-focas-enum.maxprogs`: maximum programs to list, default `100`.
- `fanuc-focas-enum.maxalarms`: maximum alarm messages to read, default `10`.
