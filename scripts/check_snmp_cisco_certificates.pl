#!/usr/bin/perl
#
# check_snmp_cisco_certificates.pl
# Perl 5.12+
#
# DATE   : Aug 18, 2026
# AUTHOR : JP Buenaventura / Copilot
#
# Nagios/Icinga compatible plugin that discovers installed PKI (X.509) certificates
# on Cisco IOS/IOS-XE WAN routers via SNMP (CISCO-PKI-MIB certChainTable) and reports
# certificate details, alerting when a certificate is approaching or past expiry.
#
# Requires CISCO-PKI-MIB support (IOS/IOS-XE 15.4+ roughly) and at least one PKI
# trustpoint/certificate installed on the router; devices with no PKI configuration
# simply report "no certificates found" (OK).
#
# Usage: check_snmp_cisco_certificates.pl -H/--hostname <host>
#            ( -C/--community <community> | --user <user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]
#              [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )
#            [-t/--timeout <seconds>] [-v/--verbose]
#            --mode MODE
#            [-w/--warning <threshold>] [-c/--critical <threshold>]
#
# Modes:
#   expiry - evaluate days remaining until expiry for every installed certificate;
#            --warning/--critical are day thresholds (default 30/10)
#   list   - list every installed certificate and its details; always OK (informational)
#

use strict;
use warnings;
use Getopt::Long;
use Net::SNMP;
use Time::Local qw(timegm);

# ==========================
# EXIT CODES
# ==========================

use constant {
    OK       => 0,
    WARNING  => 1,
    CRITICAL => 2,
    UNKNOWN  => 3,
};

my @STATUS_TEXT = ('OK', 'WARNING', 'CRITICAL', 'UNKNOWN');

# ==========================
# OIDS - CISCO-PKI-MIB (ciscoPkiMIB = ciscoMgmt.854)
# ==========================
# certChainTable is indexed by certChainLabel (a DisplayString), which is not-accessible
# and therefore never appears in a walk of its own - only columns 2..9 are walkable.
# certRemainingLife (.7) is MAX-ACCESS accessible-for-notify (trap-only), so it cannot be
# polled either; days-remaining is instead computed here from certEndDate.

my $CERT_CHAIN_ENTRY = '1.3.6.1.4.1.9.9.854.2.2.1.1';
my %COL = (
    serial  => "$CERT_CHAIN_ENTRY.2",  # certSerialNum
    issuer  => "$CERT_CHAIN_ENTRY.3",  # certIssuerName
    start   => "$CERT_CHAIN_ENTRY.4",  # certStartDate
    end     => "$CERT_CHAIN_ENTRY.5",  # certEndDate
    type    => "$CERT_CHAIN_ENTRY.6",  # certType
    tplabel => "$CERT_CHAIN_ENTRY.8",  # certTpLabel (trustpoint name)
    subject => "$CERT_CHAIN_ENTRY.9",  # certSubName
);

my %MONTH = (
    Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4,  Jun => 5,
    Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11,
);

# ==========================
# CLI OPTIONS
# ==========================

my %opt = (
    seclevel => 'authPriv',
    auth     => 'sha',
    priv     => 'aes',
    timeout  => 10,
    warning  => 30,
    critical => 10,
);

sub usage {
    my $exit = shift // UNKNOWN;
    print <<"USAGE";
Usage: $0 -H/--hostname <host>
           ( -C/--community <community> | --user <user> [--seclevel noAuthNoPriv|authNoPriv|authPriv]
             [--auth <auth-protocol>] [--authpw <auth-password>] [--priv <priv-protocol>] [--privpw <priv-password>] )
           [-t/--timeout <seconds>] [-v/--verbose]
           --mode MODE
           [-w/--warning <threshold>] [-c/--critical <threshold>]

Modes:
  expiry - evaluate days remaining until expiry for every installed certificate;
           --warning/--critical are day thresholds (default 30/10)
  list   - list every installed certificate and its details; always OK (informational)
USAGE
    exit $exit;
}

Getopt::Long::Configure(qw(no_ignore_case));

GetOptions(
    'H|hostname=s'  => \$opt{hostname},
    'C|community=s' => \$opt{community},
    'user=s'        => \$opt{user},
    'seclevel=s'    => \$opt{seclevel},
    'auth=s'        => \$opt{auth},
    'authpw=s'      => \$opt{authpw},
    'priv=s'        => \$opt{priv},
    'privpw=s'      => \$opt{privpw},
    't|timeout=i'   => \$opt{timeout},
    'v|verbose'     => \$opt{verbose},
    'mode=s'        => \$opt{mode},
    'w|warning=i'   => \$opt{warning},
    'c|critical=i'  => \$opt{critical},
    'h|help'        => sub { usage(OK) },
) or usage(UNKNOWN);

usage(UNKNOWN) unless $opt{hostname};
usage(UNKNOWN) unless $opt{mode};

unless ($opt{mode} eq 'expiry' || $opt{mode} eq 'list') {
    print "UNKNOWN: Invalid --mode '$opt{mode}'. Use 'expiry' or 'list'\n";
    exit UNKNOWN;
}

if ($opt{user}) {
    unless ($opt{seclevel} =~ /^(?:noAuthNoPriv|authNoPriv|authPriv)$/) {
        print "UNKNOWN: Invalid --seclevel '$opt{seclevel}'\n";
        exit UNKNOWN;
    }
} elsif (!$opt{community}) {
    print "UNKNOWN: Either -C/--community or --user is required\n";
    exit UNKNOWN;
}

# ==========================
# CREATE SNMP SESSION
# ==========================

my ($session, $error) = create_snmp_session(%opt);
unless ($session) {
    print "UNKNOWN: $error\n";
    exit UNKNOWN;
}

# ==========================
# FETCH CERTIFICATE TABLE
# ==========================

my $table = $session->get_table(-baseoid => $CERT_CHAIN_ENTRY);
unless (defined $table) {
    my $err = $session->error();
    $session->close();
    # A clean "no such object" response means the MIB/table simply isn't present.
    if ($err =~ /requested table is empty|no such/i) {
        print "OK: No PKI certificates found on $opt{hostname} (CISCO-PKI-MIB not populated)\n";
        exit OK;
    }
    print "UNKNOWN: $err\n";
    exit UNKNOWN;
}
$session->close();

# Group returned columns by their index suffix (the string-encoded certChainLabel).
my %certs;
for my $oid (keys %$table) {
    for my $field (keys %COL) {
        my $prefix = $COL{$field};
        if ($oid =~ /^\Q$prefix\E\.(.+)$/) {
            $certs{$1}{$field} = $table->{$oid};
            last;
        }
    }
}

unless (%certs) {
    print "OK: No PKI certificates found on $opt{hostname}\n";
    exit OK;
}

# ==========================
# EVALUATE
# ==========================

my $now = time();
my (@details, @crit_msgs, @warn_msgs, @unknown_msgs);
my $worst_days;

for my $idx (sort keys %certs) {
    my $c       = $certs{$idx};
    my $subject = $c->{subject} // 'unknown';
    my $tp      = $c->{tplabel} // 'unknown';
    my $type    = $c->{type}    // 'unknown';
    my $serial  = $c->{serial}  // 'unknown';
    my $issuer  = $c->{issuer}  // 'unknown';
    my $end_raw = $c->{end};

    my $epoch = defined $end_raw ? parse_pki_date($end_raw) : undef;

    if (!defined $epoch) {
        push @unknown_msgs, "Trustpoint=$tp Subject=$subject: could not parse expiry date '" . ($end_raw // 'n/a') . "'";
        push @details, "Trustpoint=$tp Type=$type Subject=$subject Issuer=$issuer Serial=$serial End=" . ($end_raw // 'n/a') . " (unparsable)";
        next;
    }

    my $days_left = int(($epoch - $now) / 86400);
    $worst_days = $days_left if !defined $worst_days || $days_left < $worst_days;

    my $days_text = ($days_left < 0) ? "expired " . (-$days_left) . " days ago" : "$days_left days remaining";
    push @details, "Trustpoint=$tp Type=$type Subject=$subject Issuer=$issuer Serial=$serial End=$end_raw ($days_text)";

    if ($opt{mode} eq 'expiry') {
        if ($days_left <= $opt{critical}) {
            push @crit_msgs, "Trustpoint=$tp Subject=$subject $days_text";
        } elsif ($days_left <= $opt{warning}) {
            push @warn_msgs, "Trustpoint=$tp Subject=$subject $days_text";
        }
    }
}

my $total = scalar keys %certs;

# ==========================
# OUTPUT
# ==========================

if ($opt{mode} eq 'list') {
    print "OK: $total certificate(s) found on $opt{hostname}\n";
    print join("\n", @details), "\n" if @details;
    exit OK;
}

# mode eq 'expiry'
my $perf = "certs_total=$total certs_critical=" . scalar(@crit_msgs) . " certs_warning=" . scalar(@warn_msgs);
$perf .= " days_remaining=$worst_days" if defined $worst_days;

if (@crit_msgs) {
    print "CRITICAL: " . join(", ", @crit_msgs) . " | $perf\n";
    print join("\n", @details), "\n" if $opt{verbose} && @details;
    exit CRITICAL;
}

if (@warn_msgs) {
    print "WARNING: " . join(", ", @warn_msgs) . " | $perf\n";
    print join("\n", @details), "\n" if $opt{verbose} && @details;
    exit WARNING;
}

if (@unknown_msgs && !@details) {
    # every certificate was unparsable - the check itself failed, not just a data point
    print "UNKNOWN: " . join(", ", @unknown_msgs) . "\n";
    exit UNKNOWN;
}

print "OK: $total certificate(s) OK on $opt{hostname}" . (defined $worst_days ? ", nearest expiry in $worst_days days" : '') . " | $perf\n";
if (@unknown_msgs) {
    print "Note: " . join(", ", @unknown_msgs) . "\n";
}
print join("\n", @details), "\n" if $opt{verbose} && @details;
exit OK;

# ==========================
# FUNCTIONS
# ==========================

sub create_snmp_session {
    my %o = @_;

    if ($o{user}) {
        my %v3 = (
            -hostname => $o{hostname},
            -version  => 3,
            -username => $o{user},
            -timeout  => $o{timeout},
        );

        if ($o{seclevel} eq 'noAuthNoPriv') {
            # nothing further needed
        } elsif ($o{seclevel} eq 'authNoPriv') {
            $v3{-authprotocol} = $o{auth};
            $v3{-authpassword} = $o{authpw};
        } else {
            $v3{-authprotocol} = $o{auth};
            $v3{-authpassword} = $o{authpw};
            $v3{-privprotocol} = $o{priv};
            $v3{-privpassword} = $o{privpw};
        }

        return Net::SNMP->session(%v3);
    }

    return Net::SNMP->session(
        -hostname  => $o{hostname},
        -community => $o{community},
        -version   => 2,
        -timeout   => $o{timeout},
    );
}

# Parses the DisplayString returned for certStartDate/certEndDate into a Unix epoch (UTC).
# Known/expected Cisco IOS format: "HH:MM:SS UTC Mon DD YYYY" (e.g. "08:59:59 UTC Jan 15 2025").
# Also tolerates the OpenSSL-style "Mon DD HH:MM:SS YYYY GMT" as a fallback in case the
# platform/version formats it differently. Returns undef if the string can't be parsed.
sub parse_pki_date {
    my $str = shift;
    return undef unless defined $str;

    if ($str =~ /^(\d{2}):(\d{2}):(\d{2})\s+UTC\s+(\w{3})\s+(\d{1,2})\s+(\d{4})$/) {
        my ($h, $m, $s, $mon, $day, $year) = ($1, $2, $3, $4, $5, $6);
        return undef unless exists $MONTH{$mon};
        return eval { timegm($s, $m, $h, $day, $MONTH{$mon}, $year) };
    }

    if ($str =~ /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT$/) {
        my ($mon, $day, $h, $m, $s, $year) = ($1, $2, $3, $4, $5, $6);
        return undef unless exists $MONTH{$mon};
        return eval { timegm($s, $m, $h, $day, $MONTH{$mon}, $year) };
    }

    return undef;
}
