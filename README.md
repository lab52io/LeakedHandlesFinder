# LeakedHandlesFinder
Leaked Windows processes handles identification tool

 __       __    __   _______
|  |     |  |  |  | |   ____|
|  |     |  |__|  | |  |__
|  |     |   __   | |   __|
|  `----.|  |  |  | |  |
|_______||__|  |__| |__|
==[Leaked Handles Finder v1.0 by @ramado78 from lab52.io]==================================
   Usage                   :  -r [options]
==[Options]================================================================================
   -o<file>                : Write log to file
   -s<type>                : Suspend process when a handle type (Process, File...) is found
   -a                      : AutoPwn, try to exploit the handle
   -r                      : Research mode. Keep looking for leaked handles continuously
   -l                      : Print to stdout using single line
   -h                      : Show help
   -u                      : Hide unnamed handles
   -c<Exploit command>     : Command to execute (Case process parent pid explotation)
==[Examples]===============================================================================
   Loop execution research : LeakedHandlesFinder.exe -u -r -oLogFile.txt
   One execution autopwn   : LeakedHandlesFinder.exe -u -a
