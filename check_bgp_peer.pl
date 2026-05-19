#!/usr/bin/perl
#
# check_bgp_peer.pl
# Perl 5.12+
#
# DATE   : October 20 2024
# AUTHOR : JP Buenaventura / Copilot
#
# Nagios/Icinga compatible BGP peer checker
# Supports SNMPv2c and SNMPv3
# Auto-detects Cisco platform for prefix checks
#

use strict;
use warnings;
use File::Basename;
use Net::SNMP;
use Getopt::Long;

# ==========================
# EXIT CODES
# ==========================

use constant {
    OK       => 0,
    WARNING  => 1,
    CRITICAL => 2,
    UNKNOWN  => 3,
};

# ==========================
# OIDS
# ==========================

my %OID = (
    peer_id       => '1.3.6.1.2.1.15.3.1.1',
    peer_state    => '1.3.6.1.2.1.15.3.1.2',
    peer_addr     => '1.3.6.1.2.1.15.3.1.7',
    peer_as       => '1.3.6.1.2.1.15.3.1.9',
    peer_in       => '1.3.6.1.2.1.15.3.1.12',
    peer_out      => '1.3.6.1.2.1.15.3.1.13',
    peer_uptime   => '1.3.6.1.2.1.15.3.1.16',

    # Cisco-only (CISCO-BGP4-MIB) - IOS/IOS-XE
    pfx_accepted  => '1.3.6.1.4.1.9.9.187.1.2.8.1.1',
    # Cisco-only (CISCO-BGP4-MIB v2) - IOS-XR/NX-OS
    pfx_accepted2 => '1.3.6.1.4.1.9.9.187.1.2.4.1.1',

    # Platform detection
    sys_object_id => '1.3.6.1.2.1.1.2.0',
);

my %BGP_STATE = (
    1 => 'idle',
    2 => 'connect',
    3 => 'active',
    4 => 'opensent',
    5 => 'openconfirm',
    6 => 'established',
);

# ==========================
# CLI OPTIONS
# ==========================

my %opt;
GetOptions(
    'hostname=s'  => \$opt{hostname},
    'port=i'      => \$opt{port},
    'version=s'   => \$opt{version},
    'community=s' => \$opt{community},

    # SNMPv3
    'username=s'  => \$opt{username},
    'authproto=s' => \$opt{authproto},
    'authpass=s'  => \$opt{authpass},
    'privproto=s' => \$opt{privproto},
    'privpass=s'  => \$opt{privpass},

    # Session tuning
    'timeout=i'   => \$opt{timeout},
    'retries=i'   => \$opt{retries},

    'help'        => \$opt{help},
) or usage();

usage(0) if $opt{help};
usage()  unless $opt{hostname};

$opt{port}    ||= 161;
$opt{version} ||= '2c';
$opt{timeout} //= 10;
$opt{retries} //= 2;

if ($opt{version} !~ /^(?:1|2c|2|3)$/) {
    print "UNKNOWN: Invalid SNMP version '$opt{version}'. Use 1, 2c, or 3\n";
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
# PLATFORM DETECTION
# ==========================

my $is_cisco = 0;
my $sysobj = $session->get_request(
    -varbindlist => [ $OID{sys_object_id} ]
);

if ($sysobj && ($sysobj->{ $OID{sys_object_id} } // '') =~ /^1\.3\.6\.1\.4\.1\.9\b/) {
    $is_cisco = 1;
}

# ==========================
# FETCH DATA
# ==========================

my $peer_table = $session->get_entries(
    -columns => [
        @OID{qw(
            peer_id peer_state peer_addr peer_as
            peer_in peer_out peer_uptime
        )}
    ]
) or snmp_fail($session);

my $pfx_table = {};
if ($is_cisco) {
    # Try legacy IOS/IOS-XE OID first; fall back to IOS-XR/NX-OS OID
    my $t = $session->get_table( -baseoid => $OID{pfx_accepted} );
    if (!$t || !%$t) {
        $t = $session->get_table( -baseoid => $OID{pfx_accepted2} );
    }
    $pfx_table = $t || {};
}

# ==========================
# PROCESS
# ==========================

my ($critical, $warning) = (0, 0);
my (@crit_msgs, @warn_msgs, @details);

my $peers = 0;
my $established = 0;

foreach my $oid (sort keys %$peer_table) {

    next unless $oid =~ /^\Q$OID{peer_id}\E\.(.+)$/;
    my $idx = $1;
    $peers++;

    my $state_num = $peer_table->{"$OID{peer_state}.$idx"} // 0;
    my $state     = $BGP_STATE{$state_num} || 'unknown';

    my $addr   = $peer_table->{"$OID{peer_addr}.$idx"};
    my $asn    = $peer_table->{"$OID{peer_as}.$idx"};
    my $uptime = uptime($peer_table->{"$OID{peer_uptime}.$idx"});

    push @details,
        sprintf(
            "Peer=%s ASN=%s State=%s Uptime=%s",
            $addr, $asn, $state, $uptime
        );

    if ($state ne 'established') {
        push @crit_msgs, "Peer=$addr State=$state";
        $critical = 1;
        next;
    }

    $established++;

    next if $critical;  # do not evaluate WARNINGs if CRITICAL exists

    if ($is_cisco && %$pfx_table) {
        # Match peer IP at end of OID (Cisco: .<afi>.<safi>.<peer_ip>)
        foreach my $pfx_oid (grep { /\.\Q$idx\E(?:\.|$)/ } keys %$pfx_table) {
            if ($pfx_table->{$pfx_oid} == 0) {
                push @warn_msgs, "Peer=$addr AcceptedPrefixes=0";
                $warning = 1;
            }
        }
    }
}

$session->close();

# ==========================
# NAGIOS OUTPUT
# ==========================

if ($critical) {
    print "CRITICAL: " . join(", ", @crit_msgs);
    print " | peers_total=$peers peers_established=$established peers_down=" . scalar(@crit_msgs) . "\n";
    exit CRITICAL;
}

if ($warning) {
    print "WARNING: " . join(", ", @warn_msgs);
    print " | peers_total=$peers peers_established=$established peers_warned=" . scalar(@warn_msgs) . "\n";
    exit WARNING;
}

print "OK: $established/$peers BGP peers established";
print " | peers_total=$peers peers_established=$established peers_down=0\n";
print join("\n", @details), "\n";

exit OK;

# ==========================
# FUNCTIONS
# ==========================

sub create_snmp_session {
    my %o = @_;

    if ($o{version} eq '3') {
        unless ($o{username}) {
            print "UNKNOWN: SNMPv3 requires --username\n";
            exit UNKNOWN;
        }

        my %v3 = (
            -hostname  => $o{hostname},
            -port      => $o{port},
            -version   => 3,
            -username  => $o{username},
            -timeout   => $o{timeout},
            -retries   => $o{retries},
        );

        if ($o{authpass}) {
            $v3{-authprotocol} = uc($o{authproto} || 'SHA');
            $v3{-authpassword} = $o{authpass};
        }

        if ($o{privpass}) {
            $v3{-privprotocol} = uc($o{privproto} || 'AES');
            $v3{-privpassword} = $o{privpass};
        }

        return Net::SNMP->session(%v3);
    }

    unless ($o{community}) {
        print "UNKNOWN: SNMPv2c requires --community\n";
        exit UNKNOWN;
    }

    return Net::SNMP->session(
        -hostname  => $o{hostname},
        -community => $o{community},
        -port      => $o{port},
        -version   => $o{version},
        -timeout   => $o{timeout},
        -retries   => $o{retries},
    );
}

sub uptime {
    my $s = shift;
    return '0d 0h 0m' unless defined $s && $s =~ /^\d+$/;

    my $d = int($s / 86400); $s %= 86400;
    my $h = int($s / 3600);  $s %= 3600;
    my $m = int($s / 60);

    return "${d}d${h}h${m}m";
}

sub snmp_fail {
    my $s = shift;
    print "UNKNOWN: " . $s->error . "\n";
    $s->close;
    exit UNKNOWN;
}

sub usage {
    my $rc   = shift // UNKNOWN;
    my $name = basename($0);
    print <<"END_USAGE";
Usage: $name [OPTIONS]

 SNMPv2c:
   $name --hostname <host> --community <string>
         [--port 161] [--version 1|2c]

 SNMPv3:
   $name --hostname <host> --version 3 --username <user>
         [--port 161]
         [--authproto MD5|SHA|SHA256] [--authpass <pass>]
         [--privproto DES|AES]        [--privpass <pass>]

 Required:
   --hostname  <host>  Target hostname or IP address

 Connection:
   --port      <port>  SNMP port                       (default: 161)
   --version   <ver>   SNMP version: 1, 2c, or 3       (default: 2c)
   --timeout   <sec>   SNMP timeout in seconds         (default: 10)
   --retries   <n>     SNMP retries                    (default: 2)

 SNMPv1/2c:
   --community <str>   Community string

 SNMPv3:
   --username  <user>  Username (required for v3)
   --authproto <alg>   Auth protocol: MD5, SHA, SHA256 (default: SHA)
   --authpass  <pass>  Auth passphrase
   --privproto <alg>   Priv protocol: DES, AES         (default: AES)
   --privpass  <pass>  Priv passphrase

   --help              Show this help
END_USAGE
    exit $rc;
}
