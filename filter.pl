# $Id$
# Template for perl hook
#
# API functions:
#
# w_log([level, ]str);
# outputs a string to hpt log
# no printf() format, use sprintf()!
#
# crc32(str)
# returns CRC-32 of string
#
# alike(s1, s2)
# return Levenstein distance between parameters (smaller -> more alike)
#
# putMsgInArea(area, fromname, toname, fromaddr, toaddr,
#              subject, date, attr, text, addkludges);
# post to first netmail area if area eq "";
# set current date if date eq "";
# set fromaddr to ouraka if fromaddr eq "";
# attr -- binary or text string (i.e. "pvt loc k/s") (text form DEPRECATED!);
# date -- unixtime, as in time()
# addkludges can be:
#   0 not to add any kludges
#   1 to add required kludges (will add duplicates if they exist)
#   2 to add missing kludges (will never modify existing ones)
#   3 to update or add required kludges corresponding to addresses and flags
# required kludges are: (netmail) INTL, TOPT, FMPT; (all) FLAGS, MSGID
#
# myaddr()
# returns array of our addresses
# DEPRECATED! use @{$config{addr}} instead
#
# nodelistDir()
# returns nodelistDir from config
# DEPRECATED! use $config{nodelistDir} instead
#
# str2attr(att)
# converts attribute string to binary message attributes
#
# attr2str(attr)
# converts binary flags to string representation (Pvt Loc K/s)
#
# flv2str(flavour)
# converts binary flag, corresponding to flavour, to string (direct, crash)
#
# date2fts(time)
# converts unixtime to fts-1 format string ("dd mmm yy  hh:mm:ss")
#
# fts2date(fts1)
# converts date in fts-1 format string to unixtime
#
# mktime(sec, min, hour, wday, mon, year[, wday, yday[, dst]])
# makes unixtime like POSIX mktime, but year:
#   year 0..69 -> 2000..2069, 70..1900 -> 1970..3800, other -> as-is
# month'es: 0 - January, 1 - February, ..., 11 - December (as in POSIX)
# dst - daylight saving time flag (1 or 0)
# WARNING: dst can result in +/-1 hour mismatch; use mktime(localtime) for
#          correct unixtime
#
# strftime(format, unixtime)
# strftime(format, sec, min, hour, wday, mon, year[, wday, yday[, dst]])
# converts unixtime or a time structure to string according to format
# man strftime() for details
#
# gmtoff([unixtime])
# returns difference between local time and UTC in hours (e.g., can be +4.5)
# if unixtime is omitted, current time used

sub filter
{
# predefined variables:
# $fromname, $fromaddr, $toname,
# $toaddr (for netmail),
# $area (for echomail),
# $subject, $text, $pktfrom, $date, $attr
# $secure (defined if message from secure link)
# return "" or reason for moving to badArea
# set $kill for kill the message (not move to badarea)
# set $change to update $text, $subject, $fromaddr, $toaddr,
#     $fromname, $toname, $attr
  return "";
}

sub scan
{
# predefined variables:
# $area, $fromname, $fromaddr, $toname,
# $toaddr (for netmail),
# $subject, $text, $date, $attr
# return "" or reason for dont packing to downlinks
# set $change to update $text, $subject, $fromaddr, $toaddr,
#     $fromname, $toname, $attr
# set $kill to 1 to delete message after processing (even if it's not sent)
# set $addvia to 0 not to add via string when packing
  return "";
}

sub route
{
# $addr = dest addr
# $from = orig addr
# $fromname = from user name
# $toname = to user name
# $date = message date and time
# $subj = subject line
# $text = message text
# $attr = message attributes
# $route = default route address (by config rules)
# $flavour = default route flavour (by config rules)
# set $change to update $text, $subject, $fromaddr, $toaddr,
#     $fromname, $toname, $attr
# set $flavour to flag, corresponding to flavour, 
#     or string hold|normal|crash|direct|immediate
# set $addvia to 0 not to add via string when packing
# return route addr or "" for default routing

  return "";
}

sub tossbad
{
# $fromname, $fromaddr, $toname,
# $toaddr (for netmail),
# $area (for echomail),
# $subject, $text, $pktfrom, $date, $attr
# $reason
# return non-empty string for kill the message
# set $change to update $text, $subject, $fromaddr, $toaddr,
#     $fromname, $toname, $attr
  return "";
}

sub hpt_start
{
}

sub hpt_exit
{
}

sub process_pkt
{
# $pktname - name of pkt
# $secure  - defined for secure pkt
# return non-empty string for rejecting pkt (don't process, rename to *.flt)
  return "";
}

sub pkt_done
{
# $pktname - name of pkt
# $rc      - exit code (0 - OK)
# $res     - reason (text line)
# 0 - OK ($res undefined)
# 1 - Security violation
# 2 - Can't open pkt
# 3 - Bad pkt format
# 4 - Not to us
# 5 - Msg tossing problem
}

sub after_unpack
{
}

sub before_pack
{
}

sub on_echolist
{
# $_[0] - type (0: %list, 1: %query, 2: %unlinked)
# $_[1] - reference to array of echotags
# $_[2] - link aka
# $_[3] - max tag length in @{$_[1]}
# return:
#   0 to generate hpt-standard list
#   1 to return $report value as result
#   2 to use $report value as list and append hpt standard footer
  return 0;
}

sub on_afixcmd
{
# $_[0] - command code (see #define's in areafix.h)
# $_[1] - link aka
# $_[2] - request line
# return:
#   0 to process command by hpt logic
#   1 to skip hpt logic and return $report value as result 
  return 0;
}

sub on_afixreq
{
# predefined variables:
# $fromname, $fromaddr, $toname, $toaddr. $subject, $text, $pktfrom
# return:
#   0 to ignore any changes
#   1 to update request parameters from above-mentioned variables
#     (note: only $fromaddr and $text are meaningful for processing)
  return 0;
}
