# API functions:
#
# str2attr(attr);
#
# w_log(level, str);
# no printf() format, use sprintf()!
#
# crc32(str)
#
# putMsgInArea(area, fromname, toname, fromaddr, toaddr,
#              subject, date, attr, text, addkludges);
# post to first netmail area if area eq "";
# set current date if date eq "";
# set fromaddr to ouraka if fromaddr eq "";
# attr -- text string (i.e. "pvt loc k/s");
# add kludges (INTL, FMPT, TOPT (for netmail), MSGID) if addkludges
#
# myaddr()
# returns array of our addresses
#
# nodelistDir()
# returns nodelistDir from config
#
# str2attr(att)
# converts attribute string to binary message attributes


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
# set $flavour to hold|normal|crash|direct|immediate
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
