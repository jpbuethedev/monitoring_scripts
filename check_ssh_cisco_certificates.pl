#!/usr/bin/perl
#
# check_ssh_cisco_certificates.pl
# Perl 5.12+
#
# DATE   : Aug 18, 2026
# AUTHOR : JP Buenaventura / Copilot
#
# Nagios/Icinga compatible plugin that connects to a Cisco IOS/IOS-XE WAN router over SSH,
# runs "show crypto pki certificates", and reports certificate details, alerting when a
# certificate is approaching or past expiry.
#
# Exists as an alternative to check_snmp_cisco_certificates.pl for platforms/software trains
# where CISCO-PKI-MIB is not implemented in the SNMP agent (confirmed on Cisco C1111-8P /
# IOS-XE 16.9.5 "Fuji" and 17.6.3a "Bengaluru" - the whole ciscoPkiMIB SNMP subtree is empty
# there even though certificates ARE present, e.g. the auto-generated self-signed
# "sdn-network-infra-iwan" trustpoint certificate).
#
# Requires:
#   - Network reachability to the router's SSH port (default 22) from the monitoring host.
#   - A monitoring account with SSH login and enough privilege (typically priv 15) to run
#     "show crypto pki certificates" directly - this plugin does not handle interactive
#     "enable" privilege escalation.
#   - Key-based auth is strongly preferred over --password: a password passed on the command
#     line is visible to any local user via `ps`/`/proc` on the monitoring host. --password
#     requires the `sshpass` helper to be installed.
#
# Usage: check_ssh_cisco_certificates.pl -H/--hostname <host> --user <ssh-user>
#            ( --keyfile <private-key-path> | --password <password> )
#            [-p/--port <ssh-port>] [-t/--timeout <seconds>] [-v/--verbose]
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

my %MONTH = (
    Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4,  Jun => 5,
    Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11,
);

# ==========================
# CLI OPTIONS
# ==========================

my %opt = (
    port     => 22,
    timeout  => 15,
    warning  => 30,
    critical => 10,
);

sub usage {
    my $exit = shift // UNKNOWN;
    print <<"USAGE";
Usage: $0 -H/--hostname <host> --user <ssh-user>
           ( --keyfile <private-key-path> | --password <password> )
           [-p/--port <ssh-port>] [-t/--timeout <seconds>] [-v/--verbose]
           --mode MODE
           [-w/--warning <threshold>] [-c/--critical <threshold>]

Modes:
  expiry - evaluate days remaining until expiry for every installed certificate;
           --warning/--critical are day thresholds (default 30/10)
  list   - list every installed certificate and its details; always OK (informational)

Note: --keyfile (SSH key auth) is strongly preferred over --password, which is visible via
      ps/proc on the monitoring host and requires the 'sshpass' helper to be installed.
USAGE
    exit $exit;
}

Getopt::Long::Configure(qw(no_ignore_case));

GetOptions(
    'H|hostname=s' => \$opt{hostname},
    'user=s'       => \$opt{user},
    'keyfile=s'    => \$opt{keyfile},
    'password=s'   => \$opt{password},
    'p|port=i'     => \$opt{port},
    't|timeout=i'  => \$opt{timeout},
    'v|verbose'    => \$opt{verbose},
    'mode=s'       => \$opt{mode},
    'w|warning=i'  => \$opt{warning},
    'c|critical=i' => \$opt{critical},
    'h|help'       => sub { usage(OK) },
) or usage(UNKNOWN);

usage(UNKNOWN) unless $opt{hostname};
usage(UNKNOWN) unless $opt{user};
usage(UNKNOWN) unless $opt{mode};
usage(UNKNOWN) unless $opt{keyfile} || $opt{password};

unless ($opt{mode} eq 'expiry' || $opt{mode} eq 'list') {
    print "UNKNOWN: Invalid --mode '$opt{mode}'. Use 'expiry' or 'list'\n";
    exit UNKNOWN;
}

# ==========================
# RUN REMOTE COMMAND OVER SSH
# ==========================

my ($output, $err) = run_ssh_command(%opt, command => 'show crypto pki certificates');
unless (defined $output) {
    print "UNKNOWN: $err\n";
    exit UNKNOWN;
}

# ==========================
# PARSE CERTIFICATE BLOCKS
# ==========================

my @certs = parse_pki_certificates($output);

unless (@certs) {
    print "OK: No PKI certificates found on $opt{hostname}\n";
    print "$output\n" if $opt{verbose};
    exit OK;
}

# ==========================
# EVALUATE
# ==========================

my $now = time();
my (@details, @crit_msgs, @warn_msgs, @unknown_msgs);
my $worst_days;

for my $c (@certs) {
    my $subject = $c->{subject} // 'unknown';
    my $tp      = $c->{trustpoint} // 'unknown';
    my $type    = $c->{type} // 'unknown';
    my $serial  = $c->{serial} // 'unknown';
    my $issuer  = $c->{issuer} // 'unknown';
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

my $total = scalar @certs;

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

# Runs the remote show command via the system ssh client (list-form exec, no shell
# interpolation) and returns (stdout, undef) on success or (undef, error-message) on failure.
sub run_ssh_command {
    my %o = @_;

    my @cmd;
    if ($o{password}) {
        @cmd = ('sshpass', '-p', $o{password}, 'ssh');
    } else {
        @cmd = ('ssh');
    }
    push @cmd, (
        '-o', 'BatchMode=' . ($o{password} ? 'no' : 'yes'),
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', "ConnectTimeout=$o{timeout}",
        '-p', $o{port},
    );
    push @cmd, ('-i', $o{keyfile}) if $o{keyfile};
    push @cmd, ("$o{user}\@$o{hostname}", $o{command});

    my $output = '';
    my $pid = open(my $ssh_fh, '-|');
    if (!defined $pid) {
        return (undef, "Failed to fork for ssh: $!");
    }

    if ($pid == 0) {
        # child: merge stderr into stdout and exec ssh directly (no shell)
        open(STDERR, '>&', \*STDOUT) or exit 127;
        exec(@cmd) or exit 127;
    }

    my $timed_out = 0;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($o{timeout} + 5);
        local $/;
        $output = <$ssh_fh>;
        alarm(0);
    };
    if ($@ && $@ eq "timeout\n") {
        $timed_out = 1;
        kill('TERM', $pid);
    }
    close($ssh_fh);
    my $rc = $? >> 8;

    if ($timed_out) {
        return (undef, "SSH command timed out after $o{timeout}s connecting to $o{hostname}");
    }
    if ($rc != 0) {
        my $detail = $output // '';
        $detail =~ s/\s+$//;
        return (undef, "SSH command failed (exit $rc) against $o{hostname}: $detail");
    }

    return ($output // '', undef);
}

# Parses "show crypto pki certificates" output into a list of certificate hashrefs:
# { type, serial, issuer, subject, start, end, trustpoint }
sub parse_pki_certificates {
    my $text = shift;
    my @certs;

    # Each certificate block starts with a header line naming the certificate kind and
    # runs until the next such header (or end of output).
    my @blocks = split /\n(?=(?:CA |RA |Router Self-Signed )?Certificate\s*$)/m, $text;

    for my $block (@blocks) {
        next unless $block =~ /^(?:(CA|RA|Router Self-Signed) )?Certificate\s*$/m;
        my $type = $1 // 'ID';

        my ($serial)  = $block =~ /Certificate Serial Number.*?:\s*(\S+)/;
        my ($issuer)  = $block =~ /Issuer:\s*\n\s*(.+)/;
        my ($subject) = $block =~ /Subject:\s*\n(?:\s*Name:.*\n)?\s*(.+)/;
        my ($start)   = $block =~ /start date:\s*(.+)/;
        my ($end)     = $block =~ /end\s+date:\s*(.+)/;
        my ($tp)      = $block =~ /Associated Trustpoints?:\s*(\S+)/;

        next unless defined $end || defined $subject;

        push @certs, {
            type       => $type,
            serial     => $serial,
            issuer     => $issuer,
            subject    => $subject,
            start      => $start,
            end        => $end,
            trustpoint => $tp,
        };
    }

    return @certs;
}

# Parses the "start date"/"end date" text into a Unix epoch (UTC).
# Confirmed Cisco IOS format: "HH:MM:SS UTC Mon DD YYYY" (e.g. "08:59:59 UTC Jan 15 2025").
# Also tolerates the OpenSSL-style "Mon DD HH:MM:SS YYYY GMT" as a fallback.
sub parse_pki_date {
    my $str = shift;
    return undef unless defined $str;

    if ($str =~ /^(\d{2}):(\d{2}):(\d{2})\s+UTC\s+(\w{3})\s+(\d{1,2})\s+(\d{4})/) {
        my ($h, $m, $s, $mon, $day, $year) = ($1, $2, $3, $4, $5, $6);
        return undef unless exists $MONTH{$mon};
        return eval { timegm($s, $m, $h, $day, $MONTH{$mon}, $year) };
    }

    if ($str =~ /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT/) {
        my ($mon, $day, $h, $m, $s, $year) = ($1, $2, $3, $4, $5, $6);
        return undef unless exists $MONTH{$mon};
        return eval { timegm($s, $m, $h, $day, $MONTH{$mon}, $year) };
    }

    return undef;
}
