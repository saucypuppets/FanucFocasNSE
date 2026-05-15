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

Disclaimers:
This tool is provided for authorized security testing, research, and educational purposes only. Use of this script against systems you do not own or do not have explicit written permission to test may violate local, state,
federal, or international law, including the Computer Fraud and Abuse Act (CFAA) in the United States and equivalent legislation in other jurisdictions.

OT/ICS Safety Notice: This script interacts with industrial control systems that may be connected to physical machinery. Even read-only enumeration can have unintended effects on sensitive or legacy controls, including
performance degradation, alarms, or communication faults. Do not run this script against production CNC controls or any system where unexpected behavior could result in equipment damage, production loss, or harm to
personnel. Test in an isolated lab environment first.

This software is provided "as is," without warranty of any kind, express or implied. The author assumes no liability for damages, data loss, downtime, safety incidents, or legal consequences resulting from the use or misuse
of this tool. By using this software, you accept full responsibility for its use and agree to comply with all applicable laws and regulations.
