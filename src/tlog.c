#include <log.h>

int main()
{
   s_log *log;

   log = openLog("tlog.log", "tlog v0.0.7", "abc123");
   if (NULL == log) return 1;

   writeLogEntry(log, '1', "this goes into the log");
   writeLogEntry(log, 'd', "and this not");

   closeLog(log);
   return 0;
}
