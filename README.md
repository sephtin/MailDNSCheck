## - README
#
#
## - MailDNSCheck is a Perl script that looks for changes in email related DNS records (A, MX, SPF, DKIM, DMARC).
#
## - To use the script, simply:
## - 1. Rename the DNSCheck.conf.sample to DNSCheck.conf and edit it if required.  
## - (Make sure to enable reporting and specify a recipient if you would like changes emailed to you.)
## - 2. Rename DNSCheck.txt.sample to DNSCheck.txt, and edit the file to include the domains you wish to monitor.
## - The domains should be in one of the following formats:
## - Domain.com                        If you wish to run all checks against the domain.
## - Domain.com,DKIMSelector           Required if you wish to have it monitor for DKIM changes.
## - 11111,Domain.com                  The same as just Domain.com
## - 11111,Domain.com,DKIMSelector     The same as just Domain.com,DKIMSelector
## - ... The digits in front of the domain enable or disable checks (0 for disable, 1 for enable), in the following order: A, MX, SPF, DKIM, DMARC.
## - So if you wish to ONLY check MX, SPF, and DMARC records for a domain.com, you can do so with the following entry:  01101,domain.com
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
## - Enjoy!  -John (sephtin @T gmail.com).
