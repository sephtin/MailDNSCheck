#!/usr/bin/perl
#
## - MailDNSCheck.pl - By John Ricker (sephtin ~@T~ gmail.com
##
##    Copyright (C) <2017>  <John Ricker>
##
##    This program is free software: you can redistribute it and/or modify
##    it under the terms of the GNU General Public License as published by
##    the Free Software Foundation, either version 3 of the License, or
##    (at your option) any later version.
##
##    This program is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##    GNU General Public License for more details.
##
##    You should have received a copy of the GNU General Public License
##    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
## - Requirements:
## - 1. This script takes input from a file containing the list of domains (DNSCheck.txt in the same path as the script by default).
## - Input should be in the following format:
## - For all checks, the entry can be "11111,<domain>,DKIMSelector", or simply "<domain>,<DKIMSelector>"
## - To only run specific checks:
## - "<ddddd>,<Domain>,<DKIMSelector[;another_DKIMSelector]>"
## - Where each "d"(digit) is a 0 (off) or a 1 (on) for checking each of the following protocols:
## - Protocols: A,MX,SPF,DKIM,DMARC
## - 2. rfcdiff must be installed.
## - The script expects rfcdiff to reside in an "rfcdiff" within the directory the script is run from.  You can change the path in the .conf file.
## - rfcdiff can be downloaded from: https://tools.ietf.org/tools/rfcdiff/
## - 3. wdiff is required by rfcdiff.
## - 4. Perl version newer than 5.012
## - 5. The following Perl modules:
## - -- MIME::Lite       - Used for sending attachments by email - http://search.cpan.org/~rjbs/MIME-Lite-3.030/
## - -- Log4Perl         - Used to simplify logging and fileoutputs - http://search.cpan.org/~mschilli/Log-Log4perl-1.49/
## - -- Time::Piece      - Used to simplify time/date stamping - http://search.cpan.org/~esaym/Time-Piece-1.3201/
## - -- Net::DNS         - Used for DNS lookups - http://search.cpan.org/~nlnetlabs/Net-DNS-1.11/
## - -- Config::General  - Used for config file - http://search.cpan.org/~tlinden/Config-General-2.63/
## - If you don't have permissions to install modules, if you install them to a modules directory in the same path the script is run from, it should work fine.
##
## - Once the input file contains a list of domains in the proper format, and the .conf file has your appropriate values, you should be set.
## - Enjoy!  -John
#
#
## - Changelog:
## - Version 0.01 - Initial version
## - Version 0.02 - Implemented DNS queries, custom DNS Conf file capability added.
## - Version 0.03 - Implemented proper logging and quiet mode.
## - Version 0.04 - Fixed pathing if run outside of script dir.
## - Version 0.05 - Inputfile parsed.
## - Version 0.06 - Framework for the DNS Checks has been added.
## - Version 0.07 - MX record checking has been added.
## - Version 0.08 - SPF record checking added (doesn't handle IPs/Includes).
## - Version 0.09 - A record checking added.  Output of checks now concatted into single line to make compare work.
## - Version 0.10 - Outfile and chgfile logging added.
## - Version 0.11 - Logging not respecting move of outfile to outfile_last fixed.
## - Version 0.12 - SPF recursion for INCLUDES added.
## - Version 0.13 - A and MX recursion added.
## - Version 0.14 - SPF recursion for A, added.
## - Version 0.15 - A,MX,DKIM,DMARC lookups now work.
## - Version 0.16 - Placeholders for PTR, exists, and redirect SPF lookups implemented
## - Version 0.17 - Empty lookups fixed
## - Version 0.18 - Added debugging option
## - Version 0.19 - SPF recursion for MX corrected, also now correctly counts as two lookups
## - Version 0.20 - Debug logging fixed and verbosity moved to debug.
## - Version 0.21 - Call to external rfcdiff added, comparison creates .html now
## - Version 0.22 - Reporting mailer added
## - Version 0.23 - Removed A lookups for MX reocrds, as load balanced responses break compare
## - Version 0.24 - Handling of no changes now in place -- beginning tests in Cron.
## - Version 0.25 - Extra comma due to recursion removed.
## - Version 0.26 - Additional record->type checking implemented
## - Version 0.27 - CNAME no longer breaks A, SPF, SPFComplete, Etc. lookups, sub added
## - Version 0.28 - Lookups from MX -> A -> IP removed.  Load balancers cause this to change, with no way to list and sort.
## - Version 0.29 - Requirement removed for control digits in front of domain in input file.  Now just <domain>,<DKIMSelector> is sufficient
## - Version 0.30 - date/time/datetime implemented for files and email subject
## - Version 0.31 - Work around for DMARC cnames in place.  Because: stupid people.
## - Version 0.32 - Multiple spf entries (demandnotesalerts and fiaalerts) should new be fixed.
## - Version 0.33 - Errorlog now always captures everything at a debug level, indlucing writes to outfile and chgfile.
## - Version 0.34 - Conf file added so I can release this without having to santize my personal settings for ever revision.
## - Version 0.35 - Minor bugfixes.  Reporting is now optional.  Initial public release.
#
#
## - ToDo:
## - Clean up comments/doc
## - Clean up vars, standardize on naming
## - Write subs for SPF types: exists, ptr, and redirect.
## - Implement lookup counts as specified in RFCs and include in SPF reporting (partially done)
## - Implement change/compare to each call, rather than one big diff at the end of the file.  
## - Also implement email address in inputfile, so separate email addys for individual domains is possible.
## - Merge SPF and SPFComplete and SORT (demandnotesalerts and fiaalerts fix).
## - Implement multiple DKIM selectors
## - Test Report_Sender and Report_Recipient from args
## - Args for inputfile, paths, etc.
#
#
## - Known Issues:
## - Some DNS lookups fail (MX) if Net::DNS is an old version.  Needs version checking.
## - This script doesn't lookup up the IPs of MX records as MX records are often Load Balanced making MX -> A -> IP inclusion problematic.  
## - If inputfile entry isn't formatted properly things will break. Needs error checking.
## - Multiple DKIM selectors not yet implemented.

## - Setup
use strict;
use warnings;
use 5.012;
use FindBin;
use lib "$FindBin::RealBin/modules/share/perl/5.14.2/";
use MIME::Lite;
use Log::Log4perl;
use Time::Piece;
use File::Copy qw(copy),qw(move);
use File::Compare;
use Net::DNS;
use Config::General;
open(STDERR, ">&STDOUT");

## - Define Global Vars
my ($arg,$logger,@input,$input,$check_control,$domain,$dkim_selector,@compare,$logger_conf,$lookup_count_spf,$report_subject,$res);
my $datetime = localtime->datetime;
my $time = localtime->time;
my $date = localtime->date;
my $wpath = $FindBin::Bin;  ## - Working directory. (Default: Absolute path of the script).
my $logpath = "$wpath";  ## - Common directory to store logs in (Default: wpath).
my $configfile = "$wpath/DNSCheck.conf";  ## - Config file settings over-write those within this script
my $inputfile = "$wpath/DNSCheck.txt";  ## - Name and path to file containing list of domains to check.
my $logfilename = "error.log";  ## - Name of Error log file
my $outfilename = "output.csv";  ## - Full output from current run.
my $outfile_lastname = "output_last.csv";  ## - Full output from last run.
my $chgfilename = "changes.html";  ## - Changes between current and last run - in pretty format.
my $archiveenabled = "1";  ## - Archiving of old files enabled by default.
my $archivepath = "$logpath/archived";  ## - Path to archive files
my $archivefilename = "output-$datetime.txt";  ## - Name of output archive
my $chgarchivename = "changes-$datetime.html";  ## - Name of changefile archive
my $rfcdiff = "$wpath/rfcdiff/rfcdiff";  ## - PATH to rfcdiff binary
my $reportingenabled = 0;  ## - Reporting disabled by default.  Turn it on and specify at least one recipient to enable reporting.
my $report_recipient;  ## - Recipient of email report.  Intentionally left blank.  Please specify here or in the conf file.
my $report_sender;  ## - Sender of email report.  Inteiontially left blank. If not specified, uses default account@host.domain.name of the system
my $report_mailhost = 'localhost';  ## - Only used if sending SMTP, not if mutt or injecting to sendmail with MIME::Lite
my $use_external_mta = "0";  ## - Default (0) will inject message to localhost sendmail.  To use an external mail server, set this to 1 instead.
my $quiet = '0'; ## - Defaults to verbose.  Use -q from commandline to overwrite.
my $dnsconf = "$wpath/mydns.conf";  ## - to use system DNS, comment this line out.
my $logtype = '0'; ## - Initialize the logtype var

## - Take in external .conf file (Config::General)
my $config = Config::General->new(-ConfigFile => "$configfile", -InterPolateVars => 1);
#my $config = Config::General->new(-ConfigFile => "$configfile");
my %conf = $config->getall();
$quiet = $conf{quiet} if ($conf{quiet});
$rfcdiff = $conf{rfcdiff} if ($conf{rfcdiff});
$dnsconf = $conf{dnsconf} if ($conf{dnsconf});
$inputfile = $conf{inputfile} if ($conf{inputfile});
$logpath = $conf{logpath} if ($conf{logpath});
$logfilename = $conf{logfilename} if ($conf{logfilename});
$outfilename = $conf{outfilename} if ($conf{outfilename});
$outfile_lastname = $conf{outfile_lastname} if ($conf{outfile_lastname});
$chgfilename = $conf{chgfilename} if ($conf{chgfilename});
$archiveenabled = $conf{archiveenabled} if ($conf{archiveenabled});
$archivepath = $conf{archivepath} if ($conf{archivepath});
$reportingenabled = $conf{reportingenabled} if ($conf{reportingenabled});
$report_recipient = $conf{report_recipient} if ($conf{report_recipient});
$report_sender = $conf{report_sender} if ($conf{report_sender});
$use_external_mta = $conf{use_external_mta} if ($conf{use_external_mta});
$report_mailhost = $conf{report_mailhost} if ($conf{report_mailhost});

## - Finalize global vars
my $logfile = "$logpath/$logfilename";  ## - Script output/error logging.
my $outfile = "$logpath/$outfilename";  ## - Full output from current run.
my $outfile_last = "$logpath/$outfile_lastname";  ## - Full output from last run.
my $chgfile = "$logpath/$chgfilename";  ## - Changes between current and last run - in pretty (HTML) format.
my $archivefile = "$archivepath/$archivefilename";
my $chgarchive = "$archivepath/$chgarchivename";
my $_rfcdiff = "$rfcdiff";

## - Help/Usage
sub Usage
{
  print STDERR << 'EOH';
Usage: 
$0  [-h|-help]
$0  [-q]|[-d] [-inputfile=<FileName>] [-reportrecipient=<recipient@domain.com>] [-reportsender=<sender@domain.com>]
-h for help
-q for quiet
-d for debug
-inputfile to specify a different inputfile
-reportrecipient=<recipient@domain.com>
-reportsender=<sender@domain.com>
EOH
exit 1;
}
while ($arg = shift @ARGV) {
  if ($arg =~ /^-reportrecipient=(.+\@.+)$/) {
    $report_recipient=$1;
  } elsif ($arg =~ /^-reportsender=(.+\@.+)$/) {
    $report_sender=$1;
  } elsif ($arg =~ /^-d$/) {
    if ( $quiet == 1) {
      print STDERR "Can't use both -q and -d, please choose one\n";
    Usage();
    }
    $quiet=99;
  } elsif ($arg =~ /^-q$/) {
    if ( $quiet == 99) {
      print STDERR "Can't use both -q and -d, please choose one\n";
    Usage();
    }
    $quiet=1;
  } elsif ($arg =~ /^-h$|^-help$/) {
    Usage();
  } else {
    print STDERR "Unexpected argument: $arg\n";
    Usage();
  }
}

## - Set up logging
$logger_conf = qq(
  log4perl.logger                     = DEBUG, file
  log4perl.logger.VERBOSE             = INFO, screen
  log4perl.logger.DEBUG               = DEBUG, screen
  log4perl.logger.QUIET               = DEBUG, file
  log4perl.logger.OUTFILE             = INFO, outfile
  log4perl.logger.CHGFILE             = INFO, chgfile
  log4perl.appender.file              = Log::Log4perl::Appender::File
  log4perl.appender.file.filename     = $logfile
  log4perl.appender.file.mode         = append
  log4perl.appender.file.autoflush    = 1
  log4perl.appender.file.size         = 1048576
  log4perl.appender.file.max          = 5
  log4perl.appender.file.layout       = Log::Log4perl::Layout::PatternLayout
  log4perl.appender.file.layout.ConversionPattern = %d - %p - %m %n
  log4perl.appender.screen            = Log::Log4perl::Appender::Screen
  log4perl.appender.screen.stderr     = 0
  log4perl.appender.screen.layout     = Log::Log4perl::Layout::PatternLayout
  log4perl.appender.screen.layout.ConversionPattern = %d - %p - %m %n
  log4perl.appender.outfile           = Log::Log4perl::Appender::File
  log4perl.appender.outfile.filename  = $outfile
  log4perl.appender.outfile.mode      = append
  log4perl.appender.outfile.layout    = Log::Log4perl::Layout::PatternLayout
  log4perl.appender.outfile.layout.ConversionPattern = %m%n
  log4perl.appender.chgfile           = Log::Log4perl::Appender::File
  log4perl.appender.chgfile.filename  = $chgfile
  log4perl.appender.chgfile.mode      = append
  log4perl.appender.chgfile.layout    = Log::Log4perl::Layout::PatternLayout
  log4perl.appender.chgfile.layout.ConversionPattern = %m%n
);

sub setlogging {
  $logtype = shift;
  if ($logtype) {
    if ($logtype =~ /chgfile/) {
      $logger = Log::Log4perl->get_logger('CHGFILE');
    } elsif ($logtype =~ /outfile/) {
      $logger = Log::Log4perl->get_logger('OUTFILE');
    } else {
      if ( $quiet == 1 ) {
        $logger = Log::Log4perl->get_logger('QUIET');
      } elsif ( $quiet == 99 ) {
        $logger = Log::Log4perl->get_logger('DEBUG');
      } else {
        $logger = Log::Log4perl->get_logger('VERBOSE');
      }
      print STDERR "Logtype $logtype does not exist\n";  #      $logger->info("Logtype $logtype does not exist");
    } 
  } else {
    if ( $quiet == 1 ) {
      $logger = Log::Log4perl->get_logger('QUIET');
    } elsif ( $quiet == 99 ) {
      $logger = Log::Log4perl->get_logger('DEBUG');
    } else {
      $logger = Log::Log4perl->get_logger('VERBOSE');
    }
  }  
}

## - CNAME check
sub check_cname {
  my ($lookup_cname,$record,@rr,$record_cname,@records_cname,$lookup_result_cname,@lookup_results_cname);
  $lookup_cname = shift;
  my $aaaaa = "0";  
  setlogging ();
  $logger->debug("SubCNAME- Lookup received: $lookup_cname");  
  setlogging ();
  $logger->debug("Checking CNAME record for $lookup_cname.");  
  @rr = rr($res, "$lookup_cname", "IN") or return ("CNAME record lookup failed");
  foreach $record (@rr) {
    $aaaaa = ($record->type);
    setlogging ();
    $logger->debug("SubCNAME- RecordType: $aaaaa");  
    if ($record->type eq "CNAME") {
      my $record_cname = $record->cname, ;
      setlogging ();
      $logger->debug("SubCNAME- Lookup Results: $record_cname - is a CNAME, calling check_cname again.");  
      my @lookup_results_cname = check_cname($record_cname);
      setlogging ();
      $logger->debug("Resulting CNAME lookup: @lookup_results_cname.");
      $lookup_result_cname = join(" ", @lookup_results_cname);
      setlogging ();
      $logger->debug("SubCNAME- Results received, Returning: $lookup_result_cname");  
      push @records_cname, $lookup_result_cname;
      @records_cname = sort(@records_cname);
      setlogging ();
      $logger->debug("SubCNAME- Returning result: @records_cname");  
      return @records_cname;
    } else {
      setlogging ();
      $logger->debug("SubCNAME- Result not CNAME, returning result: $lookup_cname");  
      return $lookup_cname;
    }
  }
}

sub check_a {
  my ($lookup_a,$record,@rr,$record_a,@records_a,$lookup_result_a_cname,@lookup_results_a_cname);
  $lookup_a = shift;
  setlogging ();
  $logger->debug("SubA- Received for A record lookup: $lookup_a");  
  my $aaaaa = "0";
  setlogging ();
  $logger->debug("Checking A record for $lookup_a.");  
  @rr = rr($res, "$lookup_a", ) or return ("A record lookup failed");
  foreach $record (@rr) {
    $aaaaa = ($record->type);
    setlogging ();
    $logger->debug("SubA: RecordType= $aaaaa");  
    if ($record->type eq "A") {
      $record_a = $record->address, ;
      setlogging ();
      $logger->debug("SubA Record is A: $record_a");  
      push @records_a, $record_a;
    } elsif ($record->type eq "CNAME") {
      setlogging ();
      $logger->debug("SubA Record is a CNAME.");  
      my $record_cname = $record->cname, ;
      setlogging ();
      $logger->debug("SubA= $record_cname.  Passing to check_a sub again.");  
      my @lookup_results_a_cname = check_cname($record_cname);
      $record_a = join(" ", @lookup_results_a_cname);
      setlogging ();
      $logger->debug("SubA CNAME Lookup Result: $record_a.");  
      my @records_a = check_a($record_a);
      return @records_a;
    } else {
      print "Don't know how to handle DNS query of type: $record->type\n";
    }
  }
  @records_a = sort(@records_a);
  setlogging ();
  $logger->debug("SubA-End.  Returning: @records_a.");  
  return @records_a;
}

### - A Checks
#sub check_a {
#  my ($lookup_a,$record,@rr,$record_a,@records_a);
#  $lookup_a = shift;
#  setlogging ();
#  $logger->debug("Checking A record for $lookup_a.");  
#  @rr = rr($res, "$lookup_a", "A") or return ("A record lookup failed");
#  foreach $record (@rr) {
#    $record_a = $record->address, ;
#    push @records_a, $record_a;
#  }
#  @records_a = sort(@records_a);
#  return @records_a;
#}

## - MX Checks
sub check_mx {
  my ($lookup_mx,@mx,$record,$record_mx,@records_mx);
  $lookup_mx = shift;
  setlogging ();
  $logger->debug("Checking MX record for $lookup_mx.");
  @mx = mx($res, $lookup_mx) or return ("MX record lookup failed");  ## -or  $logger->info("Can't find MX reocord for $domain ".$res->errorstring."."); ##or die "Can't find MX records for $domain (".$res->errorstring.")\n";
  foreach $record (@mx) {
    $record_mx = ($record->preference, ) . " " . ($record->exchange, );
    push @records_mx, $record_mx; 
  }
  @records_mx = sort(@records_mx);
  return @records_mx;
}

## - MX Checks -- It seems that some MX records behind a load balancer return different IPs every other lookup.. this makes it neigh impossible to diff if we do MX -> A lookups.
sub check_mx_withAlookup {
  my ($lookup_mx,@mx,$record,$record_mx,@records_mx,$lookup_result_mx,@lookup_results_mx_a,@records_mx_a,$record_mx_a);
  $lookup_mx = shift;
  setlogging ();
  $logger->debug("Checking MX record for $lookup_mx.");
  @mx = mx($res, $lookup_mx) or return ("MX record lookup failed");  ## -or  $logger->info("Can't find MX reocord for $domain ".$res->errorstring."."); ##or die "Can't find MX records for $domain (".$res->errorstring.")\n";
  foreach $record (@mx) {
    $record_mx = ($record->preference, ) . " " . ($record->exchange, );
    $record_mx_a = ($record->exchange, );
    setlogging ();
    $logger->debug("Checking A record for $record_mx_a");
    $record_mx_a =~ s/^\d+\s//;
    @lookup_results_mx_a = check_a($record_mx_a);
    @lookup_results_mx_a = sort(@lookup_results_mx_a);    
    $lookup_result_mx = join(" ", @lookup_results_mx_a);
    $lookup_result_mx = "(".$lookup_result_mx.")";
    push @records_mx_a, $record_mx_a;
    push @records_mx_a, $lookup_result_mx;
  }
  $record_mx_a = join(" ", @records_mx_a);
  @records_mx = sort(@records_mx);
  push @records_mx, $record_mx_a;
  return @records_mx;
}

## - SPF Check for complete SPF record
sub check_spf_complete {
  my (@rr,$record,$record_spf_complete,@records_spf_complete,$spf_lookup_complete);
  my $res = Net::DNS::Resolver->new( config_file => "$wpath/mydns.conf" );
  ($spf_lookup_complete) = @_;
  my $aaaaa = "0";
  setlogging ();
  $logger->debug("Checking complete SPF record for $spf_lookup_complete.");
  @rr = rr($res, "$spf_lookup_complete", "TXT") or return ("SPF record lookup failed");
  foreach $record (@rr) {
    $aaaaa = ($record->type);
    setlogging ();
    $logger->debug("SubSPFComplete RecordType= $aaaaa.");
    if ($record->type eq "CNAME") {
      my $record_spf_complete = $record->cname, ;
      setlogging ();
      $logger->debug("SubSPFComplete Found CNAME - Sending to check_cname: $record_spf_complete.");
      my @lookup_results_spf_cname = check_cname($record_spf_complete);
      $record_spf_complete = join(" ", @lookup_results_spf_cname);
      setlogging ();
      $logger->debug("SubSPFComplete Results from CNAME check: $record_spf_complete.");
      @lookup_results_spf_cname = check_spf_complete($record_spf_complete);
      $record_spf_complete = join(" ", @lookup_results_spf_cname);
      setlogging ();
      $logger->debug("SubSPFComplete Received: @lookup_results_spf_cname.  Returning: $record_spf_complete.");
      push @records_spf_complete, $record_spf_complete;
#      return @records_spf_complete;
    } else {
      $record_spf_complete = $record->txtdata, ;
      if ($record_spf_complete =~ m/spf1/i) {
        push @records_spf_complete, $record_spf_complete;
      } else {
#        print "SubSPFComplete- record not CNAME nor SPF, skipping: $record_spf_complete\n";
         next;
      }
    }
  }
  $records_spf_complete[0] //= 'SPF record lookup failed';  ## - Keeps warning for uninitialized var if resultset is empty (resulting in var being uninitialized)
  return @records_spf_complete;
}

## - SPF Checks
sub check_spf {
  my (@rr,$record,$record_spf,@records_spf,$spf_lookup,@records_spf_split,$i,$lookup,,$lookup_result,@lookup_results,@lookup_results_a_cname);
  my $res = Net::DNS::Resolver->new( config_file => "$wpath/mydns.conf" );
  ($spf_lookup) = @_;
  setlogging ();
  $logger->debug("Checking SPF record for $spf_lookup.");
  @rr = rr($res, "$spf_lookup", "TXT") or return ("SPF record lookup failed");
  foreach $record (@rr) {
    if ($record->type eq "CNAME") {
      my $record_cname = $record->cname, ;
      setlogging ();
      $logger->debug("SubSPF found CNAME - Sending to check_cname: $record_cname.");
      my @lookup_results_spf_cname = check_cname($record_cname);
      $record_spf = join(" ", @lookup_results_spf_cname);
      setlogging ();
      $logger->debug("SubSPF Results form CheckCNAME: $record_spf.");
      @lookup_results_spf_cname = check_spf($record_spf);
      $record_spf = join(" ", @lookup_results_spf_cname);
      setlogging ();
      $logger->debug("SubSPF Returning: $record_spf.");
      push @records_spf, $record_spf
#      return $record_spf;
    } else {
      $record_spf = $record->txtdata, ;
      if ($record_spf =~ m/spf1/i) {
        @records_spf_split = split / /, $record_spf;
        @records_spf_split = grep !/v=spf\d/i, @records_spf_split;
        @records_spf_split = grep !/[\?\-\~\+]all/i, @records_spf_split;
        foreach $i( 0..$#records_spf_split ) {
          setlogging ();
          $logger->debug("SPFSPLIT: $records_spf_split[$i]");
          if ($records_spf_split[$i] =~ m/v=spf\d/i) {
            push @records_spf, $records_spf_split[$i];
            next;
          } elsif ($records_spf_split[$i] =~ m/[\?\-\~\+]all/i) {
            push @records_spf, $records_spf_split[$i];
            next;
          } elsif ($records_spf_split[$i] =~ m/ip\d:/i) {
            push @records_spf, $records_spf_split[$i];
            next;
          } elsif ($records_spf_split[$i] =~ m/include:/i) {
            $lookup_count_spf = ++$lookup_count_spf;
            setlogging ();
            $logger->debug("Need to lookup INCLUDE: $records_spf_split[$i].");
            ($lookup = $records_spf_split[$i]) =~ s/include://i;
            setlogging ();
            $logger->debug("Sending off for lookup: $lookup.");
            @lookup_results = check_spf($lookup);
            $lookup_result = join(" ", @lookup_results);
            $lookup_result = "(".$lookup_result.")";
            push @records_spf, $records_spf_split[$i];
            push @records_spf, $lookup_result;
          } elsif ($records_spf_split[$i] =~ m/a:/i) {
            $lookup_count_spf = ++$lookup_count_spf;
            setlogging ();
            $logger->debug("Need to lookup A record: $records_spf_split[$i] - Count: $lookup_count_spf.");
            ($lookup = $records_spf_split[$i]) =~ s/a://i;
            @lookup_results = check_a($lookup);
            setlogging ();
            $logger->debug("Resulting A lookup: @lookup_results.");
            $lookup_result = join(" ", @lookup_results);
            $lookup_result = "(".$lookup_result.")";
            push @records_spf, $records_spf_split[$i];
            push @records_spf, $lookup_result;
          } elsif ($records_spf_split[$i] =~ m/^mx$/i) {
            $lookup_count_spf = ++$lookup_count_spf;
            setlogging ();
            $logger->debug("Need to lookup MX record: $spf_lookup - Count: $lookup_count_spf.");
            my @lookup_results_spf_mx = check_mx($spf_lookup);
#            setlogging ();
#            $logger->debug("Need to lookup resulting A record: @lookup_results_spf_mx - Count: $lookup_count_spf.");
#            my @lookup_results_spf_a;
#            foreach my $lookup_spf_mx (@lookup_results_spf_mx) {
#              next if ($lookup_spf_mx eq "MX record lookup failed");
#              $lookup_spf_mx =~ s/^\d+\s//;
#              $lookup_count_spf = ++$lookup_count_spf;
#              @lookup_results_spf_a = check_a($lookup_spf_mx);
#              setlogging ();
#              $logger->debug("Resulting A lookup: @lookup_results_spf_a.");
#              $lookup_result = join(" ", @lookup_results_spf_a);
#              $lookup_result = "(".$lookup_result.")";
#              push @lookup_results, $lookup_spf_mx;
#              push @lookup_results, $lookup_result;
#              setlogging ();
#              $logger->debug("SPF MX check complete: @lookup_results.");
#            }
#            $lookup_result = join(" ", @lookup_results);
            $lookup_result = join(" ", @lookup_results_spf_mx);
            $lookup_result = "(".$lookup_result.")";
            push @records_spf, $records_spf_split[$i];
            push @records_spf, $lookup_result;
#          } elsif ($records_spf_split[$i] =~ m/ptr:/i) {  ## - PTR Lookups.
#            $lookup_count_spf = ++$lookup_count_spf;
#            setlogging ();
#            $logger->debug("Need to lookup PTR reoord: $records_spf_split[$i] - Count: $lookup_count_spf.");
#            ($lookup = $records_spf_split[$i]) =~ s/a://i;
#            @lookup_results = check_a($lookup);
#            setlogging ();
#            $logger->debug("Resulting PTR lookup: @lookup_results.");
#            $lookup_result = join(" ", @lookup_results);
#            $lookup_result = "(".$lookup_result.")";
#            push @records_spf, $records_spf_split[$i];
#            push @records_spf, $lookup_result;
#          } elsif ($records_spf_split[$i] =~ m/redirect:/i) {  ## - redirect lookups.
#            $lookup_count_spf = ++$lookup_count_spf;
#            setlogging ();
#            $logger->debug("Need to lookup Redirect record: $records_spf_split[$i] - Count: $lookup_count_spf.");
#            ($lookup = $records_spf_split[$i]) =~ s/a://i;
#            @lookup_results = check_a($lookup);
#            setlogging ();
#            $logger->debug("Resulting Redirect lookup @lookup_results");
#            $lookup_result = join(" ", @lookup_results);
#            $lookup_result = "(".$lookup_result.")";
#            push @records_spf, $records_spf_split[$i];
#            push @records_spf, $lookup_result;
#          } elsif ($records_spf_split[$i] =~ m/exists:/i) {  ## - exists lookups
#            $lookup_count_spf = ++$lookup_count_spf;
#            setlogging ();
#            $logger->debug("Need to lookup Exists record.");
#            ($lookup = $records_spf_split[$i]) =~ s/a://i;
#            @lookup_results = check_a($lookup);
#            setlogging ();
#            $logger->debug("Resulting Exists lookup: @lookup_results.");
#            $lookup_result = join(" ", @lookup_results);
#            $lookup_result = "(".$lookup_result.")";
#            push @records_spf, $records_spf_split[$i];
#            push @records_spf, $lookup_result;
          }
          setlogging ();
          $logger->debug("SPF_COMBINE: @records_spf.");
          $logger->debug("SPFLookupCount= $lookup_count_spf.");
        }
      }
    }
  }
return (@records_spf);
}

## - DKIM Checks
sub check_dkim {
  my ($lookup_dkim,@rr,$record,$record_dkim,@records_dkim,$lookup_selector);
  ($lookup_dkim, $lookup_selector) = @_;
#  return ("DKIMSelector Unknown") unless ($lookup_selector);
  unless ($lookup_selector) {
    setlogging ();
    $logger->debug("Checking DKIM record failed for $domain.  DKIMSelector Unknown.");
    return ("DKIMSelector Unknown");
  }
  setlogging ();
  $logger->debug("Checking DKIM record for $lookup_dkim with selector $lookup_selector.");
#  @rr = rr($res, "$lookup_selector\._domainkey\.$lookup_dkim", "TXT");  ## - !!! Not sure if the .'s need to be escaped!!!
  @rr = rr($res, "$lookup_selector\._domainkey\.$lookup_dkim", "TXT") or return ("DKIM record lookup failed");
  foreach $record (@rr) {
    $record_dkim = $record->txtdata, ;
    if ($record_dkim =~ m/dkim/i) {
      push @records_dkim, $record_dkim;
    }
  }
  return (@records_dkim);
  setlogging ("outfile");
  $logger->info("_DKIM,$lookup_dkim,@records_dkim");
  setlogging ();
  $logger->debug("SUB_DKIM-Returning: _SPF,$lookup_dkim,@records_dkim");
}

## - DMARC Checks
sub check_dmarc {
  my ($lookup_dmarc,@rr,$record,$record_dmarc,@records_dmarc);  
  $lookup_dmarc = shift;
  setlogging ();
  $logger->debug("Checking DMARC record for $lookup_dmarc.");
  @rr = rr($res, "_dmarc\.$lookup_dmarc", "TXT") or return ("DMARC record lookup failed");
  foreach $record (@rr) {
    if ($record->type eq "CNAME") {
      $record_dmarc = "DMARC record invalid";
    } else {
      $record_dmarc = $record->txtdata, ;
    }
    if ($record_dmarc =~ m/dmarc/i) {
      push @records_dmarc, $record_dmarc;
    }
  }
  return (@records_dmarc);
  setlogging ("outfile");
  $logger->info("_DMARC,$lookup_dmarc,@records_dmarc");
  setlogging ();
  $logger->debug("SUB_DMARC-Returning: _DMARC,$lookup_dmarc,@records_dmarc");
}

## - Reporting
sub mailer_mutt {
  system "mutt -e 'set content_type=text/html' -s '$report_subject' -a '$outfile' -a '$outfile_last' -a '$chgfile' -- '$report_recipient' < $chgfile";
}

sub mailer {
  my @mailer_args = @_;
  setlogging ();
  $logger->debug("Setting up mailer- Subject:$mailer_args[0], Body: $mailer_args[1], Attachment1: $mailer_args[2]");
  sleep(2);
  my $msg;
  if ($report_sender) {  ## - If sender specified, set the sending address.
    $msg = MIME::Lite->new (  ## - Create the multipart container
    From => $report_sender,
    To => $report_recipient,
    Subject => $mailer_args[0],
    Type =>'multipart/mixed'
    ) or die "Error creating multipart container: $!\n";
  } else {
    $msg = MIME::Lite->new (  ## - Create the multipart container
    To => $report_recipient,
    Subject => $mailer_args[0],
    Type =>'multipart/mixed'
    ) or die "Error creating multipart container: $!\n";
  }
  $msg->attach ( ## - Add the changes html as the message body
  Type => 'text/html',
  Path => $mailer_args[1],
  Filename => $mailer_args[1]
  ) or die "Error adding the text message part: $!\n";
  $msg->attach ( ## - Add the first file
  Type => 'text/plain',
  Path => $mailer_args[2],
  Filename => $mailer_args[2],
  Disposition => 'attachment'
  ) or die "Error adding $outfile: $!\n";
  if ($mailer_args[3]) {
    $msg->attach ( ## - Add the second file
    Type => 'text/plain',
    Path => $mailer_args[3],
    Filename => $mailer_args[3],
    Disposition => 'attachment'
    ) or die "Error adding $outfile_last: $!\n";
  }
  if ($mailer_args[4]) {
    $msg->attach (  ## - Add the third file
    Type => 'text/html',
    Path => $mailer_args[4],
    Filename => $mailer_args[4],
    Disposition => 'attachment'
    ) or die "Error adding $chgfile: $!\n";
  }
  if ($use_external_mta == 1) {
    MIME::Lite->send('smtp', $report_mailhost, Timeout=>60);  ## - Send to external server, otherwise inject to local MTA
  }
  $msg->send or print "failed for some reason: $!\n";  ## - Send the message - Inject to MTA unless prev. line is uncommented
}

####################
###  Begin Work  ###
####################

## - File management
if ($archiveenabled == 1) {
  if ( !-d $archivepath ) {
    make_path $archivepath or die "Failed to create path: $archivepath";  ## - Create archvied dir if doesn't exist
  }
  if (-s $chgfile) {
    rename("$chgfile", "$chgarchive") or die "Cannot rename $chgfile: $!";
#    move $chgfile, "$chgarchive";  ## - archive changefile
  }
  if ( -s $outfile_last) { 
    if (-s $archivefile) {
      unlink($archivefile);
    }
    rename("$outfile_last", "$archivefile") or die "Cannot rename $outfile_last: $!";
  }
}
if ( -s $outfile) { 
  if (-s $outfile_last) {
    unlink($outfile_last);
  }
  rename("$outfile", "$outfile_last") or die "Cannot rename $outfile: $!";
#  move $outfile, $outfile_last;  ## - Rotate outfile to outfile_last
}
if (-s $logfile) {
  unlink($logfile);
}

## - Initialize Logging
Log::Log4perl::init( \$logger_conf );  ## - Initialize Logger
setlogging ();  ## - Set logger to correct output

## - Debug Info
setlogging ();
$logger->debug("wpath= $wpath");
$logger->debug("Version of Net::DNS=" . Net::DNS->version );
$logger->debug("Version of Perl= $^V");
$logger->debug("Date/Time/DateTime=$date/$time/$datetime");

## - Setting up DNS
if ( -s $dnsconf ) { 
  $res = Net::DNS::Resolver->new( config_file => "$dnsconf" );  ## - In order to use external DNS server, use DNSCONF file rather than default DNS provided by the system.
} else {
  $res = Net::DNS::Resolver->new();
}

## - Parse inputfile
open (INPUTFILE, "<", "$inputfile") or $logger->logdie("Can't open file for reading: $!");  #or die "Cannot open file for reading: $!";
@input = <INPUTFILE>;
chomp (@input);
close (INPUTFILE);

## - Begin Checks
if (@input) {
  foreach $input (@input) {
    next if($input =~ /^$/);
    next if($input =~ /^#/);
    setlogging ("outfile");
    $logger->info("\#\# - INPUT=$input");
    if ( $input =~ m/^[01]{5}/ ) {
      ($check_control,$domain,$dkim_selector) = split(/,/, $input);
    } else {
      $check_control = "11111";
      ($domain,$dkim_selector) = split(/,/, $input);
    }
    #print "Controls=$check_control\n";
    #print "Domain=$domain\n";
    #print "DKIM_Selector=$dkim_selector\n";  ## - May be empty.. throws an error on the print statement, but will be corrected for in parsing.
    if ( substr($check_control, 0,1) == 1 ) {  ## - Start processing A records.
      setlogging ();
      $logger->debug("Subbing A record for $domain.");
      my @results_a = check_a($domain);
      setlogging ("outfile");
      $logger->info("_A,$domain,@results_a");
      setlogging ();
      $logger->info("_A,$domain,@results_a");
    }
    if ( substr($check_control, 1,1) == 1 ) {
      setlogging ();
      $logger->debug("Subbing MX record for $domain.");
      my @results_mx = check_mx($domain);
      setlogging ("outfile");
      $logger->info("_MX,$domain,@results_mx");
      setlogging ();
      $logger->info("_MX,$domain,@results_mx");
    }
    if ( substr($check_control, 2,1) == 1 ) {
      setlogging ();
      $logger->debug("Subbing SPF Complete record for $domain.");
      my @results_spf_complete = check_spf_complete($domain);
      setlogging ();
      $logger->debug("Results from SPFComplete: _SPF,$domain,@results_spf_complete");
      $lookup_count_spf = "0";
      if ( $results_spf_complete[0] ne "SPF record lookup failed") {
        setlogging ();
        $logger->debug("Subbing SPF record for $domain.");
        my @results_spf = check_spf($domain);
        setlogging ("outfile");
        $logger->info("_SPF,$domain,@results_spf_complete,@results_spf");
        setlogging ();
        $logger->info("_SPF,$domain,@results_spf --- COUNT: $lookup_count_spf");
      } else {
        setlogging ("outfile");
        $logger->info("_SPF,$domain,@results_spf_complete");
        setlogging ();
        $logger->info("_SPF,$domain,SPF lookup failed - skipping SPF checks.");
      }
    }
    if ( substr($check_control, 3,1) == 1 ) {
      my @results_dkim;
      unless ($dkim_selector) {
        setlogging ();
        $logger->debug("No DKIMSelector provided for $domain.");
        @results_dkim = "DKIMSelector Unknown";
      } else {
        setlogging ();
        $logger->debug("Subbing DKIM record for $domain.");
        @results_dkim = check_dkim($domain, $dkim_selector);
      }
      setlogging ("outfile");
      $logger->info("_DKIM,$domain,@results_dkim");
      setlogging ();
      $logger->info("_DKIM,$domain,@results_dkim");
    }
    if ( substr($check_control, 4,1) == 1 ) {
      setlogging ();
      $logger->debug("Subbing DMARC record for $domain.");
      my @results_dmarc = check_dmarc($domain);
      setlogging ("outfile");
      $logger->info("_DMARC,$domain,@results_dmarc");
      setlogging ();
      $logger->info("_DMARC,$domain,@results_dmarc");
    }
  }
} else {
  setlogging ();
  $logger->logdie("No input detected in $inputfile");
}

## - Begin Compare 
if (compare("$outfile_last","$outfile") == 0) {  ## - If files are the same...
  if ($reportingenabled != 0 ) {
    $report_subject = "Mail DNS Check - $datetime - No changes.";
    mailer($report_subject,$logfile,$outfile,$logfile);  ## - Mail subject, body, 1 attachment
    setlogging ();
    $logger->info("Reporting enabled, sending message...");
  }
} else {
  system "$_rfcdiff --hwdiff --larger $outfile_last $outfile $chgfile >> $chgfile";
  if ($reportingenabled != 0 ) {
    $report_subject = "Mail DNS Check - $datetime - Has changed!";
    mailer($report_subject,$chgfile,$outfile,$outfile_last,$chgfile);  ## - Mail subject,body,3 attachments
    setlogging ();
    $logger->info("Reporting enabled, sending message...");
  }
}

exit 0;
