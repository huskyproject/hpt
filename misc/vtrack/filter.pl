use vtrack;
use nidx qw(ncheck hub region nodeline);
sub w_log;
# --------------------------------------------------------------------
sub filter {
  if (!defined $area) { process_netmail(); } else { process_echomail(); }
  undef $change if $kill;  # need not to change if it's killed anyway
  return '';
}
# --------------------------------------------------------------------
sub process_netmail {
  w_log "process_netmail(): $sfrom ($from) -> $sto ($to) [".attr2str($attr)."]; pkt from $pktfrom (secure=$secure)";
  my @points = qw(2:463/180.8 2:550/180.8);
  (my $to3 = $to) =~ s/\.\d+$//;
  (my $from3 = $from) =~ s/\.\d+$//;
  my $aux = "pkt from $pktfrom, ".($secure ? "" : "un")."secure";
  # kill netmail to me from daemons
  # ping
  if (me($to) && (lc $sto eq 'ping')) {
    if ($attr & RRC) {
      post('MAIL.BAD', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
           "\x01Reason: Ping request with RRC flag\r".$text, 0);
      $kill = 1;
      return;
    }
    my $dt = strftime("%d %b %Y %H:%M:%S");
    response('ping', $sfrom, $from, "Ping reply",
             "Your message has reached my system at $dt",
             "Ваше сообшение достигло моей системы $dt");
    $kill = 1;
    return;
  }
  # rrq/arq to me
  if (me($to) && $attr & (RRQ|ARQ)) {
    if ($sto =~ /areafix|hpt|crashmail|ffix|allfix|filefix|vtrack/io) {
      post('MAIL.BAD', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
           "\x01Reason: RRQ/ARQ to robot\r".$text, 0);
      $kill = 1;
      return;
    }
    if ($attr & RRC) {
      post('MAIL.BAD', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
           "\x01Reason: RRQ/ARQ with RRC flag\r".$text, 0);
      $kill = 1;
      return;
    }
    my $dt = strftime("%d %b %Y %H:%M:%S");
    response('rrq', $sfrom, $from, "Return receipt response", 
             "Your message has been received at $dt",
             "Ваше сообщение получено $dt");
  }
  # move my personal mail to inbox, send copy to my point
  if ( me($to) && $sto =~ /(?:^val|k?hok?hlo|sysop)/io ) {
    post('MAIL.RCV', $sfrom, $sto, $from, $to, $subj, $date, 
         ($attr|RCV)&~LOC, $text, 0);
    $offs = gmtoff(); $offs = ($offs) ? sprintf("%+g", $offs) : '';
    my $fwd = "\x01Forwarded by $to \@".strftime("%Y%m%d.%H%M%S")."UTC$offs\r";
    post('NETMAIL', $sfrom, $sto, $from, '2:550/180.8', $subj, $date, 
         ($attr|TRS|K_S)&~(LOC|ATT|FRQ|URQ|KFS|TFS|HLD|CRA|DIR|IMM|ARQ|RRQ), $fwd.$text, 3);
    $new_mail++;
    $kill = 1;
    return;
  }
  # save a copy of my home point mail here
  if ( $to =~ m!(?:463|550)/180\.8$!o && $sto =~ /(?:^val|k?hok?hlo|sysop)/io ) {
    my $fwd = "\x01Forwarded for $to \@".strftime("%Y%m%d.%H%M%S")."UTC$offs\r";
    post('MAIL.RCV', $sfrom, $sto, $from, '2:550/180', $subj, $date, 
         ($attr|RCV)&~LOC, $fwd.$text, 1);
  }
  # move other mail to my node to local netmail for robots to process
  if ( me($to) ) {
    return if $sto =~ /^(areafix|areamgr|hpt)$/oi;   # hpt process on fly
    post('MAIL.LOC', $sfrom, $sto, $from, $to, $subj, $date, $attr&~LOC, $text, 0);
    $kill = 1;
    return;
  }
  # not for me -- rewrite message flags
  my $unsafe = HLD|CRA|DIR|IMM|LOC|A_S;
  if ($attr & $unsafe) { $attr &= ~$unsafe; $change = 1; }
  if (!($attr & (TRS|K_S))) { $attr |= TRS|K_S; $change = 1; }
  # not for me -- fix fileattaches (path, KFS)
  if ($attr & ATT) {
    if ($attr & TFS) { $attr &= ~TFS; $change = 1; }
    if (!($attr & KFS)) { $attr |= KFS; $change = 1; }
    $change |= att_conv();
  }
  # move messages from me to bad
  if ( me($from) ) {
    post('MAIL.BAD', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
         "\x01Reason: Non-local message from me ($aux)\r".$text, 3);
    $kill = 1;
    return;
  }
  # move messages with unknown sender and recipient to bad
  if ( !me($to3) && !me($from3) && !ncheck($from3) && !ncheck($to3) ) {
    post('MAIL.BAD', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
         "\x01Reason: Sender and recipient unlisted ($aux)\r".$text, 3);
    $kill = 1;
    return;
  }
  # move unsecure messages with unknown sender to bad
  if ( !$secure && !ncheck($pktfrom) ) {
    post('MAIL.BAD', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
         "\x01Reason: Unsecure and pkt sender unknown ($aux)\r".$text, 3);
    $kill = 1;
    return;
  }
  # reject messages with unknown my point
  if ( me($to3) && !in(\@points, $to) ) {
    post('MAIL.BAD', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
         "\x01Reason: Unknown my point ($aux)\r".$text, 3);
    bounce('warn', $sfrom, $from, "Mail delivery warning",
           "your message reached its destination node, but destination point is unknown", 
           "ваше сообщение пришло на узел назначения, но у меня нет такого пойнта");
    $kill = 1;
    return;
  }
  # reject messages with unknown recipient
  if ( !me($from) && !me($to3) && !ncheck($to3) ) {
    bounce('nl', $sfrom, $from, "Mail delivery failure",
           "recipient node address is unlisted", 
           "адрес узла получателя не найден в нодлисте");
    att_kill(); $kill = 1;
    return;
  }
  # reject attaches to unprotected links
  if ( !me($from) && !me($to3) && ($attr & ATT) && !$links{$to3} && !$links{$to} ) {
    bounce('', $sfrom, $from, "Mail delivery failure",
           "attaches to non-direct links are not allowed",
           "аттачи на непарольных линков не разрешены");
    att_kill(); $kill = 1;
    return;
  }
  # check netmail loops
  my $lc = loop_cnt();
  my $la = loop_age(0);
  if ($lc > 7 || $la > 7) {
    bounce('', $sfrom, $from, "Mail delivery failure",
           "too many loops detected", 
           "сообщение зацикливается при прохождении через мой узел");
    att_kill(); $kill = 1;
    return;
  }
  elsif ($lc > 0) {
    post('MAIL.HLD', $sfrom, $sto, $from, $to, $subj, $date, $attr, 
         "\x01vtrack: Hold until \@".strftime("%Y%m%d.%H%M%S", time+24*3600)." at $config{addr}[0]\r".$text, 3);
    $kill = 1;
    return;
  }
  # check max age
  if (age() > 30) {
    bounce('', $sfrom, $from, "Mail delivery failure",
           "message is already too old", 
           "cообщение слишком старое");
    att_kill(); $kill = 1;
    return;
  }
  # incomplete file attaches - hold message for an hour
  if ( !me($from) && !att_check() ) {
    post('MAIL.HLD', $sfrom, $sto, $from, $to, $subj, $date, $attr, 
         "\x01vtrack: Hold until \@".strftime("%Y%m%d.%H%M%S", time+3600)." at $config{addr}[0]\r".$text, 3);
    $kill = 1;
    return;
  }
}
# --------------------------------------------------------------------
sub process_echomail {
  w_log "process_echomail(): area $area, $sfrom -> $sto; pkt from $pktfrom (secure=$secure)";
  my $aux = "pkt from $pktfrom, ".($secure ? "" : "un")."secure";
  # should not even be here
  if (!$secure) {
    post('BADECHO', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
         "\x01Reason: Echomail in unsecure packet ($aux)\r".$text, 0);
    $kill = 1;
    return;
  }
  # carbon copy personal mail
  if ( lc $sto eq 'val khokhlov' ) {
    post('PERSONAL', $sfrom, $sto, $from, $to, $subj, $date, $attr & ~(LOC), 
         "AREA:$area\r".$text, 0);
  }
}
# --------------------------------------------------------------------
sub scan {
  if ($area !~ /^(?:NETMAIL|MAIL\.)/io) { w_log "scan(): area $area; $sfrom -> $sto"; }
    else { w_log "scan(): netmail $sfrom ($from) -> $sto ($to) [".attr2str($attr)."] in area $area"; }
  # hold messages
  if (uc $area eq 'MAIL.HLD') {
    if ($text =~ /(?:^|\r)\x01vtrack:[^\@]*\@(\d{4})(\d{2})(\d{2})\.(\d{2})(\d{2})(\d{2})/) {
      my $t = mktime($6, $5, $4, $3, $2-1, $1);
      if ($t >= time) { return 'to be held for '.($t - time).'s'; }
      $text =~ s/(^|\r)\x01vtrack:[^\r]+\r/$1/;
    }
    post('NETMAIL', $sfrom, $sto, $from, $to, $subj, $date, $attr, $text, 0);
    $kill = 1; $new_mail++;
    return 'moved to netmail';
  }
  # netmail areas
  elsif (uc $area eq 'NETMAIL' || $area =~ /^[Mm][Aa][Ii][Ll]\./o) {
    # strip vtrack kludges - they're supposed to be local
    if ($text =~ /(^|\r)\x01(vtrack:|Reason:)[^\r]+\r/) {
      $text =~ s/(^|\r)\x01(vtrack:|Reason:)[^\r]+\r/$1/g;
      $change = 1;
    }
    # my outgoing messages - move to sent
    if (!($attr & K_S) && (uc $area eq 'MAIL.RCV' || 
        (uc $area eq 'NETMAIL' && me($from) && ($attr & LOC)))) {
      post('MAIL.SNT', $sfrom, $sto, $from, $to, $subj, $date, $attr|SNT, $text, 0);
    }
    # check attached files
    if (!me($from) && !att_check()) {
      bounce('warn', $sfrom, $from, "Mail delivery warning",
             "some of the attached files are absent - sending message without them",
             "некоторые из приаттаченных файлов отсутствуют - сообщение уйдет без них");
    }
    # warn about unknown sender address
    if ( !($attr & LOC) && !me($from3) && !ncheck($from) ) {
      bounce('warn nl', $sto, $to, "Mail delivery warning",
             "sender node address is unlisted - please don't reply via standard routing", 
             "адрес узла отправителя не найден в нодлисте - пожалуйста, не отвечайте по стандартному роутингу");
    }
    # don't keep messages in work area
    $kill = 1;
    return '';
  }
  # others
  return '';
}
# --------------------------------------------------------------------
sub route {
  w_log "route(): msg $sfrom ($from) -> $sto ($to) [".attr2str($attr)."]";
  $route = undef; $flavour = undef; my @routes; $addvia = 0;
  (my $to3 = $to) =~ s/\.\d+$//;
  my ($tohub, $toreg) = (hub($to3), region($to3));
  # route my points
  if (me($to3)) { $flavour = HLD; $route = $to; }
  # route local direct messages
  elsif ($attr & (LOC|DIR)) { $flavour = DIR; $route = $to; }
  # protected links direct hub-routing
  elsif (defined $links{$to3}) { $route = $to3; }
  elsif ($to3 !~ m!^2:550?/! && defined $links{$tohub}) { $route = $tohub; }
  # n463
  elsif ($tohub eq '2:463/0' || $tohub eq '2:463/59') { $route = '2:463/59'; }
  elsif ($tohub eq '2:463/220') { $route = '2:463/220'; }
  elsif ($tohub eq '2:463/2223') { $route = '2:463/2223'; }
  elsif ($to3 =~ m!^2:463/!) { @routes = qw'2:463/220 2:463/59 2:463/2223'; }
  # n464
  elsif ($to3 =~ m!^2:464/!) { @routes = qw'2:464/910 2:550/4077'; }
  # n465
  elsif ($to3 =~ m!^2:465/!) { @routes = qw'2:465/204 2:5020/52'; }
  # n467
  elsif ($to3 =~ m!^2:467/!) { @routes = qw'2:5080/111 2:5020/52'; }
  # n469
  elsif ($to3 =~ m!^2:469/!) { @routes = qw'2:469/418 2:463/220'; }
  # n5010
  elsif ($to3 =~ m!^2:5010/!) { @routes = qw'2:5010/252 2:5020/52'; }
  # n5080
  elsif ($to3 =~ m!^2:5080/!) { @routes = qw'2:5080/111 2:5020/52'; }
  # n550
  elsif ($to3 eq '2:550/4077' || $to3 eq '2:550/5012') { $flavour = CRA; $route = '2:550/4077'; }
  # r45
  elsif ($toreg eq '2:45') { @routes = qw'2:450/42 2:5020/52'; }
  # r46
  elsif ($toreg eq '2:46') { @routes = qw'2:463/220 2:5020/52'; }
  # r50
  elsif ($toreg eq '2:50') { @routes = qw'2:5020/52 2:463/220'; }
  # r55
  elsif ($toreg eq '2:55') { @routes = qw'2:550/0 2:550/4077'; }
  # world
  else { $route = '2:550/0'; }
  # check re-packing
  my $rep = pack_age(); my $lim = 2; my $try = 0;
  if (@routes) {
    # how many tries was made
    while ($rep > $lim) { $try++; $lim *= 2; }
    w_log "route(): [note] try ".($try+1)." of ".scalar(@routes) if $try > 0;
    # try link
    $try = 0 if $try >= @routes;
    ($flavour, $route) = $routes[$try] =~ /^([cihd])?(.*)/o;
  }
  if (!defined $rep) {
    # ping
    my $dt = strftime("%d %b %Y %H:%M:%S");
    if (defined $route && (lc $sto eq 'ping')) {
      response('tracert', $sfrom, $from, "Traceroute reply",
               "Your message was routed to $route by my system at $dt",
               "Ваше сообшение направлено на $route с моей системы $dt");
    }
    # arq
    if ($attr & ARQ) {
      response('arq', $sfrom, $from, "Audit response", 
               "Your message was routed to $route by my system at $dt",
               "Ваше сообшение направлено на $route с моей системы $dt");
    }
    # add via
    addvia($route) if defined $route;
  }
  # set flavour from links, if unknows - to hold
  $flavour = (defined $links{route}) ? $links{$route}{flavour} : 0 unless defined $flavour;
  w_log "route(): route='$route', flavour='".flv2str($flavour)."'; defined=".(defined $flavour ? 1 : 0);
  return $route;
}
# --------------------------------------------------------------------
sub hpt_start {
  nidx::init($config{'nodelistDir'}, nidx, {soft_net=>1, ok_zone=>[1..6], w_log=>1});
  nidx::update('nodelist\.\d{3}', 'net_463\.\d{3}:2:46');
  $new_mail = $new_echo = 0;
}

sub hpt_exit {
  nidx::done;
  close FLG if $new_mail && open FLG, ">/home/val/fido/flags/pack.now";
  close FLG if $new_echo && open FLG, ">/home/val/fido/flags/scan.now";
}

sub in {
  my ($arr, $val) = @_;
  for my $v (@$arr) { return 1 if $v eq $val; }
  return 0;
}
# --------------------------------------------------------------------
# bounce($type, $toname, $toaddr, $subj, $eng, $rus)
sub bounce {
  my ($type, $_sto, $_to, $_subj, $eng, $rus) = @_;
  my $fromstr = sprintf("%-36s%-17s%s", $sfrom, $from, strftime("%d %b %y %H:%M:%S", $date));
  my $tostr   = sprintf("%-36s%-17s",   $sto, $to);
  (my $kludges = msg_kludges()) =~ tr[\x01][\@];
  (my $vias    = msg_vias())    =~ tr[\x01][\@];
  my ($eng_hdr, $rus_hdr, $eng_nls, $rus_nls);
  if ($type =~ /warn/) {
    $eng_hdr = 'Your message is accepted for delivery with the following warning:';
    $rus_hdr = 'Ваше сообщение принято к доставке со следующим предупреждением:';
  } else {
    $eng_hdr = 'Delivery of your message is cancelled because of the following reason:';
    $rus_hdr = 'Доставка вашего сообщения прекращена по следующей причине:';
  }
  if ($type =~ /nl/) { 
    $eng_nls = $rus_nls = join ' ', nidx::nodelists; 
    $eng_nls = "Following nodelists used for check: $eng_nls\n";
    $rus_nls = "При проверке использованы нодлисты: $rus_nls\n";
  }
  my $s = <<EOM
Greetings, $_sto!

$eng_hdr
 * $eng
${eng_nls}Original message follows

$rus_hdr
 * $rus
${rus_nls}Оригинальное сообщение следует ниже

=<==========================================================================<=
 From: $fromstr
 To  : $tostr
 Subj: $subj
==============================================================================
$kludges

... message body skipped ... текст сообщения пропущен ...

$vias
=<==========================================================================<=

--- $hpt_ver+vtrack $VERSION
EOM
;
  post('NETMAIL', 'vtrack', $_sto, '2:550/180', $_to, $_subj, time, PVT|LOC|K_S, $s, 1);
  $new_mail++;
}
# --------------------------------------------------------------------
# response($type, $toname, $toaddr, $subj, $eng, $rus)
sub response {
  my ($type, $_sto, $_to, $_subj, $eng, $rus) = @_;
  my $fromstr = sprintf("%-36s%-17s%s", $sfrom, $from, strftime("%d %b %y %H:%M:%S", $date));
  my $tostr   = sprintf("%-36s%-17s",   $sto, $to);
  (my $vias    = msg_vias())    =~ tr[\x01][\@];
  my $s = <<EOM
Greetings, $_sto!

$eng
Original message header and Via lines follow

$rus
Заголовок оригинального сообщения и строки Via следуют ниже

=<==========================================================================<=
 From: $fromstr
 To  : $tostr
 Subj: $subj
==============================================================================
$vias
=<==========================================================================<=

--- $hpt_ver+vtrack $VERSION
EOM
;
  post('NETMAIL', 'vtrack', $_sto, '2:550/180', $_to, $_subj, time, PVT|LOC|K_S|RRC, $s, 1);
  $new_mail++;
}
