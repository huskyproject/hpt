#!/usr/bin/perl

# This small perl script produce html-formatted output for postings into
# "documentation" area of http://sourceforge.net/projects/husky
#
# (c) Stas Degteff 2:5080/102

print "<pre>\n";
while( <> ){
 chomp;

 if( /\[(\d+)\]/ ){ print "<a name=$1></a>"; }
 s/^(.*\[\d+\].*)$/<h3>$1<\/h3>/;
 s/^(Q: .*)$/<font color=blue>$1<\/font>/;
 s/^(A:.*)$/<\/font><font color=brown>$1<\/font>/;
 s/ *\/-+\/ */<hr>/;
 s/Q(\d+)(\. .*)$/<a href=\#$1>Q$1$2<\/a>/;

 print "$_\n";
}
print "</pre>\n";
