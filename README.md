# FanucFocasNSE
`focas-info.nse` enumerates a Fanuc CNC controller exposing FOCAS over Ethernet, normally on TCP/8193.

The script performs read-only queries with raw packets:

- Controller model, family, version, and axis information.
- Run, mode, alarm, emergency, and edit status.
- Active program details.
- Lists all programs accesible in CNC_MEM

Developed against a bare-bones 0i-MD control. Needs validation against additional families of CNC control, Data Server, and FAST ethernet cards. 

Example output:
`PORT     STATE SERVICE REASON         VERSION
8193/tcp open  focas   syn-ack ttl 64 Fanuc FOCAS 2 (Ethernet) 0i-MD (series D4F1, version 37.0)
| focas-info: 
|   System: 
|     Model: 0i-MD
|     Control: 0i
|     Machine: Milling
|     Series: D4F1
|     Version: 37.0
|     Axes: 03
|     Capabilities: i-Series
|   Status: 
|     Mode: MDI
|     Run State: (reset)
|     Motion: none
|     Aux Signal: none
|     Alarm: ALARM
|     Emergency: EMERGENCY STOP
|     Edit: not editing
|   Active Program: 
|     Running O-number: O5112
|     Main O-number: O5112
|     Sequence: 0
|     Executing O-number: O5112
|     Program Name: O5112
|   Programs: 
|     Count: 37
|     Source: CNC memory
|     Entries: 
|       O0090     500 B  ()
|       O0249    1500 B  (SHAVE 5MM 73.1)
|       O0545     500 B  ()
|       O0671     500 B  ()
|       O0703    1000 B  ()
|       O0731     500 B  ()
|       O0741     500 B  ()
|       O0871     500 B  ()
|       O1993    3500 B  (OPEN BORE 87.1 CHAMFER)
|       O1994    4500 B  (OPEN BORE 130.2 CHAMFER)
|       O1995    4000 B  (OPEN BORE 117.1 CHAMFER)
|       O1996    4000 B  (OPEN BORE 108.1 CHAMFER)
|       O1997     500 B  (DRILL-PRO 8 LUG)
|       O1998     500 B  (DRILL-PRO 6 LUG)
|       O1999     500 B  (DRILL-PRO 4 LUG)
|       O2444    1500 B  (OPEN BORE 73.1 CHAMFER)
|       O2445    2000 B  (OPEN BORE 74.1 CHAMFER)
|       O2499     500 B  (CHAMFER ONLY 73.1 DEFAULT)
|       O2501     500 B  (DRILL-PRO DUAL 4 LUG)
|       O2600    2000 B  (SHAVE 15MM 74.1)
|       O2601    3000 B  (SHAVE 20MM 73.1)
|       O2603    2500 B  (SHAVE 20MM 74.1)
|       O2999     500 B  (DRILL-PRO DUAL)
|       O3001    2000 B  (OPEN BORE ONLY 73.1 25MM)
|       O3002    2000 B  (OPEN BORE ONLY 74.1 25MM)
|       O3010    2000 B  (SHAVE 15MM 73.1)
|       O3333     500 B  (CHAMFER ONLY 74.1 DEFAULT)
|       O3881     500 B  (DRILL-PRO)
|       O3882     500 B  (DRILL-PRO DEEP)
|       O5112     500 B  ()
|       O5115     500 B  ()
|       O5120     500 B  ()
|       O7999    2000 B  (OPEN BORE 110 CHAMFER)
|       O8000    2000 B  (FANUCT20 48 HOUR TEST)
|       O8989     500 B  (WARM UP)
|       O9004     500 B  (T24 TOOL CHANGE)
|_      O9014     500 B  ()`




Disclaimers:
This tool is provided for authorized security testing, research, and educational purposes only. Use of this script against systems you do not own or do not have explicit written permission to test may violate local, state,
federal, or international law, including the Computer Fraud and Abuse Act (CFAA) in the United States and equivalent legislation in other jurisdictions.

OT/ICS Safety Notice: This script interacts with industrial control systems that may be connected to physical machinery. Even read-only enumeration can have unintended effects on sensitive or legacy controls, including
performance degradation, alarms, or communication faults. Do not run this script against production CNC controls or any system where unexpected behavior could result in equipment damage, production loss, or harm to
personnel. Test in an isolated lab environment first.

This software is provided "as is," without warranty of any kind, express or implied. The author assumes no liability for damages, data loss, downtime, safety incidents, or legal consequences resulting from the use or misuse
of this tool. By using this software, you accept full responsibility for its use and agree to comply with all applicable laws and regulations.
