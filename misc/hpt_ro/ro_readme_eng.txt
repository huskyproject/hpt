Hpt_ro English readme: $Id$

     ABOUT
     -----
In most cases, readonly restriction abilities of the HPT are enough.
Sometimes however an echoarea should be protected from a group of links with 
some exceptions only or a readonly restriction period should expire. In these 
situations HPT cannot offer anything convenient.
Fortunately HPT has a very powerful feature named perl hooks. If you need 
complex readonly but you don't know perl or you are too lazy to grub about in 
perl scripts, this program package is for you.

    FILES
    ------

Hpt_ro.pm - program library. It is a core of the package.

ro_parser.pl - similar to tparser.exe: it prints result of config-files 
               processing.

ro_purge.pl - to clear hpt_ro config-file of expired rules. Execute this script
              sometimes (by task scheduler or manually).

ro.cfg - hpt_ro config-file example.

ro_readme_en.txt - this manual.

ro_readme_rus.txt - this manual in Russian.


    SETUP
    -----

Before setup make sure you have installed HPT with perl hooks enabled and perl 
(v5.6.0 or newer).

1. Copy the files to a destination directory. It can be HPT directory but it 
is not a must. The only requirement is that ro_parser.pl, ro_purge.pl and 
Hpt_ro.pm must be in the same directory.

2. Adjust the paths in Hpt_ro.pm to your actual configuration:

  my $defhptconf = "n:\\bin\\hpt\\config";
  $ro_conf = "n:\\bin\\hpt\\ro.cfg";

The first string defines the HPT config-file name. The FIDOCONFIG environment 
variable overrides this definition. 
The second string contains hpt_ro config-file name. This file can have any name 
and can be placed anywhere you want. I will refer to this file as 'ro.cfg' in 
this document.

Notice: you should use double back slashes instead of single ones.

3. Create new ro.cfg file or edit the sample one. 

4. Check ro.cfg with ro_parser.pl. This script can produce a large output so 
it is better to redirect the output to a file:

  perl ro_parser.pl > ro.txt

If you want to see restricted links only, use the 'denyonly' parameter:

  perl ro_parser.pl denyonly > ro.txt

5. If the result of the previous checking is OK, it's time to change 
filter.pl. Insert the following lines at the beginning of the filter.pl:

  use lib "n:\\bin\\hpt";
  use Hpt_ro;

Specify the full path to the Hpt_ro.pm in the double quotes after 'use lib' 
statement. Don't forget to use double back slashes instead of single ones.

Add the following lines to the filter() function:

  if ($area) {
    my $res = Hpt_ro::checkro($area,$pktfrom);
    return $res if $res;
  }


6. Execute the filter.pl script to check if everything is ok:

  perl filter.pl

7. Setup finished.


     A T T E N T I O N !
     -------------------


After each time you change ro.cfg you should execute ro_parser.pl to make sure 
the config-file is free of errors. An incorrect config-file will cause 
filter.pl run-time error. 
If HPT detects error(s) during filter.pl compilation or 
execution it will disable perl hooks. So one stupid misprint may crash down 
all your security settings.


     ro.cfg format
     -------------

The ro.cfg config-file is a sequence of groups definitions and rules.
The group must be defined before its first usage.

GROUP OF ECHOES is defined by 'echogroup' keyword.

To define a group you can use the single-line syntax:

 echogroup <groupname> echomask1 echomask2 ...

If an group of echoes contains many echoes the multi-line syntax can be more 
useful:

 echogroup <groupname>
   echomask1 echomask2 echomask3 ...
   echomaski echomaski+1 ...
   ...
   echomaskn-1 echomaskn
 endechogroup

You can define several groups with the same name. In this case echo lists are 
merged. Example:

 echogroup sysops R50.SYSOP*
 echogroup sysops N5020.SYSOP*

is equal to

 echogroup sysops R50.SYSOP* N5020.SYSOP*


GROUP OF LINKS definition has the same syntax as the group of echoes.

 linkgroup <groupname> linkmask1 linkmask2 ...

or

 linkgroup <groupname>
   linkmask1 linkmask2 linkmask3 ...
   linkmaski linkmaski+1 ...
   ...
   linkmaskn-1 linkmaskn
 endlinkgroup

The linkmask format is d:d/d[.d], where 'd' is a number or an asterisk (*).
Link 'd:d/d.0' is an equivalent of 'd:d/d', so the point with zero number and 
the node addresses are the same.

NOTES:
- group names are CASE SENSITIVE (sysops and SYSOPS groups are different).
- echo and link groups are in the different name spaces, therefore they may
have the same names without problems. That's why 'all' link group and 'all'
echo group are absolutely different.
- echo group name cannot begin with hyphen ('-'). 

RULES have the following syntax:

{deny|allow} {@linkgroup|linkmask} {@echogroup|echomask} [expiration date]

linkgroup - previously defined link group. You must add the symbol '@' before
  the group name.
linkmask - link or link mask;
echogroup - previously defined echo group. You must add the symbol '@' before
  the group name. A group name beginning with hyphen ('-') refers to a HPT 
  echo group ('-g' options in an echo area definition). I.e., '@-A' means 'all 
  echoes that are defined as 'A' echo group members according to the HPT 
  config-file'.
echomask - echo name or mask;
expiration date - last date of the rule validity. After this date the rule is 
  ignored and can be erased by ro_purge.pl. Date format is 'dd.mm.yy', where 
  'dd' - day of month (1..31), 'mm' - month (1..12), 'yy' - year (00..99).
  If the expiration date is omitted the rule is enabled forever.

Roughly speaking, rules work as follows: every combination of echo and link,
passed to the checkro() function, is compared with every rule
(one by one in the order specified in the config-file). The first rule
matching both the echo and the link designate write access (allow or deny).

Examples:

- Deny write access for all points except 2:6037/1.28:

  allow 2:6037/1.28 OSCOL.SYSOPS
  deny 2:6037/1.* OSCOL.SYSOPS

- Forbid points to write to the sysops' echoes:

echogroup sysopechoes R50.SYSOP* N5020.SYSOP*
deny 2:6037/1.* @sysopechoes

- Moderator prohibited 2:6037/1.* to write to SUPER.ECHO till 31st December 
2001 inclusively:

  deny 2:6037/1.* SUPER.ECHO 31.12.01

- A node has some uplinks and downlinks. The node receives some readonly 
echoes from the uplinks. We must forbid our downlinks to write to the echoes.

  # The mask '*:*/*.*' means 'all links'. The mask '*:*/*' is not applicable
  # because it means 'all nodes' and is equivalent to the mask '*:*/*.0'.
  linkgroup all *:*/*.*
  
  # uplinks group
  linkgroup uplinks 2:5020/52 2:5025/3 2:6037/9
  
  # readonly echoes
  echogroup readonly
    HUMOR.FILTERED 
    1072.COMPNEWS            
    BOCHAROFF.MUST.DIE  BOCHAROFF.UNPLUGGED   
  endechogroup
  
  # allow the uplinks to write ...
  allow @uplinks @readonly
  #  ...but forbid other links
  deny @all @readonly

Theoretically in the example above one uplink has write access to the readonly 
echo, received from another uplink. Some action should be done to prevent this 
security breach. First of all, in HPT config-file the same unique group should 
be configured for each echoes received from the same uplink. Let's assume for 
example that echoes from 2:5020/52 have group 'A', from 2:5025/3 group 'B' and 
from 2:6037/9 group 'C'. Appropriate 'linkgrp' configuration also should be 
done to provide correct groups for autocreated echoes. After the HPT 
config-file was properly changed it is time to change ro.cfg:

  linkgroup all *:*/*.*
  echogroup readonly
    HUMOR.FILTERED 
    1072.COMPNEWS            
    BOCHAROFF.MUST.DIE  BOCHAROFF.UNPLUGGED   
  endechogroup
  # allow the uplinks to write to 'their' readonly echoes
  allow 2:5020/52 @-A
  allow 2:5025/3 @-B
  allow 2:6037/9 @-C
  # prevent others from writing to readonly echoes
  deny @all @readonly
  

     HOW DOES IT WORK
     ----------------

At the first call the checkro() function reads HPT config-file and ro.cfg.
Then all links of all echoes are checked for the ro.cfg rules match. 
Results of the check are two two-dimensional hashes (associative arrays) 
'allow' and 'deny'. If a link-echo pair, passed to the checkro(), is in the 
allow hash the link is allowed to write to the echo. If the pair is in 
the deny hash the link is prohibited to write to the echo.
If a link-echo pair is neither in the deny hash nor in the allow hash the 
config-files will be reread. This situation may be caused by the following 
circumstances:
1. The echo did not exist when tossing had started.
2. The link doesn't exist in the HPT config-file.
3. The link is not subscribed to the echo.
4. The link was not subscribed to the echo but he has subscribed and written a 
letter to the echo straightway.

The 1st, 2nd and 3rd cases could be processed by HPT itself without Hpt_ro help.
The config-file rereading is necessary only for the correct processing of the 
4th case.


     LICENSE
     -------

The Advanced Readonly package is freely distributed software. It is
distributed As Is with no warranty. You use this package at your own risk!

You may use the package by any means and where you want. You may use parts of 
the package in your own software. Copyright may be preserved but it's not
required. 


     THANKS
     ------

Many thanks to: 
- HPT developers - for a convenient and reliable tosser;
- Perl authors - for the universal instrument for lazy sysadmins; :)
- Fyodor Ustinov - for some ideas and FTrack;
- all good FIDO members - for your existence.


     ENGLISH VERSION EDITOR
     ----------------------

Igor Zakharoff (2:5030/290.36)


     AUTHOR
     ------

Author: Andrew Sagulin
FIDO:  2:6037/1.28
e-mail: andrews42@users.sourceforge.net
ICQ: 128724384

