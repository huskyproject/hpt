# Extracting rules from echoareas: perl hook
# Freeware (c) Rostislav Podgorniy 2:4635/83
# Insert this code into filter.pl 
# or specify this file in HPTPerlFile fidoconfig statement
#
#= ru.husky (2:5080/102) ============================================ ru.husky =
# From : Rostislav Podgorniy                 2:4635/83       22 Feb 03  10:10:02
# Subj : Re: выдирание правил из эх
#===============================================================================
#■ Привет, Anton!
#
#21 фев 03 Anton Konstantinov писал на тему "выдирание правил из эх"
#
# RP>>   Сделал выдирания правил из эх. Реализовано на перловых хуках.
# RP>>   Кому надо, могу поделиться :)
#
# AK> поделись буду очень признателен...
#
#=== Hачало filter.pl ===

sub after_unpack {
# Called after unpacking an echomail bundle to TempInbound
}

sub before_pack {
# Called before packing echomail bundle to one of links
}

sub process_pkt {
# Called before processing pkt, the following variables available:
#   $pktname - name of pkt,
#   $secure - defined if this pkt from secure link
# hook must return "" for normal pkt processing or other string to rename pkt to .flt
}

sub pkt_done{
# Called after pkt processing, the following variables available:
#   $pktname - name of pkt,
#   $rc - exit code(0-ok),
#   $res - reason(exit code in text form):
#     0 - OK ($res undefined),
#     1 - Security violation,
#     2 - Can't open pkt,
#     3 - Bad pkt format,
#     4 - Not to us,
#     5 - Msg tossing problem
}

sub hpt_exit {
# Called before hpt completely exit if any other Perl hook was called during this session.
  unlink("e:\\nnode\\other\\temp\\rules.make");
}

sub route {
# Called just before routing netmail message, the following variables availble:
#   $addr - message destination address,
#   $from - message originating address,
#   $toname - destination user name,
#   $fromname - originating user name,
#   $subject - message subject line,
#   $date - message date and time,
#   $text - message text,
#   $attr - message attributes,
#   $route - default route for this message (derermined via Route statements in config file
#   (may be empty, this means that either no route at all for this message or it will be routed
#   via one-to-multi routing(Route normal noroute 2:5004/73.*)).
# Before return you can set $flavour - to hold|normal|crash|direct|immediate for required
# flavour of message.
# return "" for default routing or address via which this message should be sent. example:
#     sub route {
#     if ($from eq "2:5004/75.73") return "2:5004/75.0";
#     else return "";
#     }
}

sub scan {
# Called while scanning messages (hpt scan or hpt pack). The following variables available:
#   $fromname - originating user name,
#   $fromaddr - message originating address,
#   $toname - destination user name,
#   $toaddr - message destination address (for netmail),
#   $area - message area (for echomail),
#   $subject - message subject line,
#   $date - message date and time,
#   $text - message text,
#   $attr - message attributes.
# Set $change to update $text, $subject, $fromaddr, $toaddr, $fromname, $toname, $attr.
# If returns non-empty string (reason), the message will not pack to downlinks.
}

sub filter {
# Called for processing every message while tossing. The following variables available:
#   $fromname - originating user name,
#   $fromaddr - message originating address,
#   $toname - destination user name,
#   $toaddr - message destination address (for netmail),
#   $area - message area (for echomail),
#   $subject - message subject line,
#   $date - message date and time,
#   $text - message text,
#   $attr - message attributes,
#   $pktfrom - address of originating pkt,
#   $secure - defined if the message received from secure link.
# Set $change to update $text, $subject, $fromaddr, $toaddr, $fromname, $toname, $attr.
# Set $kill for kill message.
# If returns non-empty string (reason), the message will be moved to badarea.

  use POSIX;
  use locale;

  my($rules_file,@rules_subj,@temp,$temp_one,$i,$k);
  local(*F);
  @rules_subj = qw(
    rules
    ╞Ю═╒╗╚═
    ОПЮБХКЮ
  );
  $i=0;
  foreach (@rules_subj) {
    if ($subject =~ /$_/i) {
      if ($fromname =~ /moder/i) {

    open(F,"e:\\nnode\\other\\temp\\rules.make");
    @temp = <F>;
    close(F);
    foreach $temp_one (@temp) {
      chop $temp_one;
      if ($temp_one eq $area) {$i++;}
    }

    if ($i == 0) {$k="l";} else {$k=$i;}
    $rules_file="e:\\nnode\\other\\rules\\".lc($area).".ru".$k;
        open(F, ">".$rules_file);
        print F deltechinfo("$text");
        close(F);

        open(F, ">>e:\\nnode\\other\\temp\\rules.make");
        print F "$area\n";
        close(F);
      }
    }
  }
  return "";
}

sub deltechinfo {
  my(@temp,$temp_once,@newtemp,$i);

  @temp=split(/\r/,$_[0]);
  $i=0;
  foreach (@temp) {
    if (not(/@/i or /SEEN-BY/i or /Origin:/i or /-[-]+/i or /\.\.\./i)) {
      $newtemp[$i]=$_;
      $i++;
    }
  }
  $temp_once=join("\r",@newtemp);
  return $temp_once;
}

sub tossbad {
# Called when message will be put in badArea. The following variables available:
#   $fromname - originating user name,
#   $fromaddr - message originating address,
#   $toname - destination user name,
#   $toaddr - message destination address (for netmail),
#   $area - message area (for echomail),
#   $subject - message subject line,
#   $date - message date and time,
#   $text - message text,
#   $attr - message attributes,
#   $pktfrom - address of originating pkt,
#   $reason - reason, why badarea (text string).
# Set $change to update $text, $subject, $fromaddr, $toaddr, $fromname, $toname, $attr.
# If returns non-empty string (reason) for kill the message.
}
#=== Конец filter.pl ===
#
#--
#WBR, Rostislav Podgorniy      rostislav[ @ ]podgorniy.com      icq #709057
#
#... Сто грамм - не стоп кран - дернешь, не остановишься.
#--- GoldED+ 1.1.5-30120 (WinNT 5.1.2600-Service_Pack_1 i686)
# * Origin: evlix.com.ua - Evlix Net Group (Design, Programming, ... (2:4635/83)
