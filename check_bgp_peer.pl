#!/usr/bin/perl
#
# check_bgp_peer.pl
# Perl 5.12+
#
# DATE   : May 26, 2026
# AUTHOR : JP Buenaventura / Copilot
#
# Nagios/Icinga compatible BGP & EIGRP peer checker
# Supports SNMPv2c and SNMPv3
# Auto-detects routing protocol (BGP or EIGRP)
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

    # EIGRP (CISCO-EIGRP-MIB) - peer table columns
    eigrp_peer_table   => '1.3.6.1.4.1.9.9.449.1.4.1',
    eigrp_peer_ifindex => '1.3.6.1.4.1.9.9.449.1.4.1.1.3',
    eigrp_peer_hold    => '1.3.6.1.4.1.9.9.449.1.4.1.1.4',
    eigrp_peer_uptime  => '1.3.6.1.4.1.9.9.449.1.4.1.1.5',
    eigrp_peer_srtt    => '1.3.6.1.4.1.9.9.449.1.4.1.1.6',
    eigrp_peer_rto     => '1.3.6.1.4.1.9.9.449.1.4.1.1.7',

    # Platform detection
    sys_descr     => '1.3.6.1.2.1.1.1.0',
    sys_object_id => '1.3.6.1.2.1.1.2.0',

    # Hardware model (ENTITY-MIB) — index 1 = chassis
    ent_model     => '1.3.6.1.2.1.47.1.1.1.1.13.1',
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
    -varbindlist => [ $OID{sys_object_id}, $OID{sys_descr} ]
);

unless ($sysobj) {
    # Device did not respond at all — no point trying further queries
    my $err = $session->error // 'No response';
    print "UNKNOWN: $err ($opt{hostname})\n";
    $session->close;
    exit UNKNOWN;
}

if (($sysobj->{ $OID{sys_object_id} } // '') =~ /^1\.3\.6\.1\.4\.1\.9\b/) {
    $is_cisco = 1;
}

# Extract router model — prefer ENTITY-MIB entPhysicalModelName (hardware)
my $model = 'unknown';
{
    my $ent = $session->get_request(
        -varbindlist => [ $OID{ent_model} ]
    );
    if ($ent) {
        my $val = $ent->{ $OID{ent_model} } // '';
        # Ignore noSuchObject / noSuchInstance responses
        $model = $val if $val =~ /\S/ && $val !~ /noSuch/i;
    }
    # Fallback: parse image name from sysDescr
    if ($model eq 'unknown') {
        my $descr = $sysobj->{ $OID{sys_descr} } // '';
        if ($descr =~ /\((\S+)\)/) {
            $model = $1;
        }
    }
}

# Known router models — add new entries as they are confirmed
my %known_models = map { $_ => 1 } (
    'C881-K9',           'CISCO881-SEC-K9',  'CISCO2801',
    'CISCO2901/K9',      'CISCO1921/K9',     'CISCO887-SEC-K9',
    'CISCO886VA-SEC-K9', 'CISCO881-K9',      'CISCO876-K9',
    'CISCO871-K9',       'C886VA-K9',        'C881G+7-K9',
    'C881G-4G-GA-K9',
);

# ==========================
# FETCH DATA & DETECT PROTOCOL
# ==========================

my $protocol = '';
my $peer_table;
my $eigrp_table;
my $pfx_table = {};

# Try BGP first (standard BGP4-MIB, works on any vendor)
$peer_table = $session->get_entries(
    -columns => [
        @OID{qw(
            peer_id peer_state peer_addr peer_as
            peer_in peer_out peer_uptime
        )}
    ]
);

if ($peer_table && %$peer_table) {
    $protocol = 'BGP';

    if ($is_cisco) {
        # Try legacy IOS/IOS-XE OID first; fall back to IOS-XR/NX-OS OID
        my $t = $session->get_table( -baseoid => $OID{pfx_accepted} );
        if (!$t || !%$t) {
            $t = $session->get_table( -baseoid => $OID{pfx_accepted2} );
        }
        $pfx_table = $t || {};
    }
}

# No BGP peers → try EIGRP (CISCO-EIGRP-MIB)
if (!$protocol) {
    $eigrp_table = $session->get_table(
        -baseoid => $OID{eigrp_peer_table}
    );

    if ($eigrp_table && %$eigrp_table) {
        $protocol = 'EIGRP';
    }
}

if (!$protocol) {
    print "UNKNOWN: No BGP or EIGRP peers found on $opt{hostname}\n";
    $session->close;
    exit UNKNOWN;
}

# ==========================
# PROCESS
# ==========================

my ($critical, $warning) = (0, 0);
my (@crit_msgs, @warn_msgs, @details);

my $peers = 0;
my $established = 0;

if ($protocol eq 'BGP') {

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

} elsif ($protocol eq 'EIGRP') {

    # EIGRP peers present in the table are up; down peers disappear.
    my %seen_idx;

    # Fetch ifDescr table for interface-name mapping
    my %if_name;
    my $if_table = $session->get_table(
        -baseoid => '1.3.6.1.2.1.2.2.1.2'
    );
    if ($if_table) {
        while (my ($k, $v) = each %$if_table) {
            $if_name{$1} = $v if $k =~ /\.(\d+)$/;
        }
    }

    foreach my $oid (sort keys %$eigrp_table) {
        next unless $oid =~ /^\Q$OID{eigrp_peer_ifindex}\E\.(.+)$/;
        my $idx = $1;
        next if $seen_idx{$idx}++;

        $peers++;
        $established++;

        my ($idx_addr, $as_num) = parse_eigrp_index($idx);
        my $col3 = $eigrp_table->{"$OID{eigrp_peer_ifindex}.$idx"} // '';
        my $hold = $eigrp_table->{"$OID{eigrp_peer_hold}.$idx"}    // 'N/A';

        # Column .3 varies by IOS version:
        #   - Standard MIB: cEigrpPeerIfIndex (integer)
        #   - C881 / older IOS: peer IP as printable string ("10.1.2.3")
        #   - Some IOS: peer IP as 4 raw bytes (Hex-STRING)
        my ($addr, $iface);
        if ($col3 =~ /^\d{1,3}(?:\.\d{1,3}){3}$/) {
            # Printable dotted-decimal IP string
            $addr  = $col3;
            $iface = '';
        } elsif ($col3 =~ /^0x([0-9a-f]{8})$/i) {
            # Hex-encoded IPv4 (Net::SNMP translated OCTET STRING)
            $addr  = join('.', map { hex($_) } ($1 =~ /../g));
            $iface = '';
        } elsif ($col3 =~ /^\d+$/) {
            # Numeric ifIndex
            $addr  = $idx_addr;
            $iface = '';
            if ($col3 > 0 && exists $if_name{$col3}) {
                $iface = " If=$if_name{$col3}";
            }
        } elsif (length($col3) == 4) {
            # 4 raw bytes — binary IPv4 address (translate disabled)
            $addr  = join('.', unpack('C4', $col3));
            $iface = '';
        } else {
            $addr  = $idx_addr;
            $iface = '';
        }

        # Columns .5 and .6 may be swapped on some IOS versions.
        # Detect by content: uptime has non-digit chars ("1w3d", "03:34:25"),
        # SRTT is purely numeric (milliseconds).
        my $val5 = $eigrp_table->{"$OID{eigrp_peer_uptime}.$idx"};
        my $val6 = $eigrp_table->{"$OID{eigrp_peer_srtt}.$idx"};

        my ($up_str, $srtt);
        if (defined $val6 && $val6 =~ /\D/) {
            # .6 has non-digit chars → it is the uptime string
            $up_str = $val6;
            $srtt   = $val5 // 'N/A';
        } elsif (defined $val5 && $val5 =~ /\D/) {
            # .5 has non-digit chars → standard layout
            $up_str = $val5;
            $srtt   = $val6 // 'N/A';
        } else {
            # Both numeric — assume standard MIB order
            $up_str = $val5 // 'N/A';
            $srtt   = $val6 // 'N/A';
        }

        push @details,
            sprintf(
                "Peer=%s ASN=%s%s HoldTime=%ss SRTT=%sms Uptime=%s",
                $addr, $as_num, $iface, $hold, $srtt, $up_str
            );
    }

    if ($peers == 0) {
        push @crit_msgs, "No EIGRP neighbors found";
        $critical = 1;
    }
}

$session->close();

# ==========================
# NAGIOS OUTPUT
# ==========================

my $model_tag = ($model ne 'unknown') ? " [$model]" : '';

if ($critical) {
    print "CRITICAL: " . join(", ", @crit_msgs) . $model_tag;
    print " | peers_total=$peers peers_established=$established peers_down=" . scalar(@crit_msgs) . "\n";
    exit CRITICAL;
}

if ($warning) {
    print "WARNING: " . join(", ", @warn_msgs) . $model_tag;
    print " | peers_total=$peers peers_established=$established peers_warned=" . scalar(@warn_msgs) . "\n";
    exit WARNING;
}

my $proto_msg = ($protocol eq 'EIGRP') ? "BGP not active. EIGRP" : $protocol;
print "OK: $established/$peers $proto_msg peers established${model_tag}";
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

sub parse_eigrp_index {
    my $idx = shift;
    # Index varies by IOS version.  Try several known layouts.
    my @p = split /\./, $idx;
    my $n = scalar @p;

    # Format A: vpnId.asNum.addrType(1).addrLen(4).b1.b2.b3.b4  (8 elements)
    if ($n >= 8 && $p[2] == 1 && $p[3] == 4 && _all_octets(@p[4..7])) {
        return (join('.', @p[4..7]), $p[1]);
    }
    # Format B: vpnId.asNum.addrType(1).b1.b2.b3.b4  IMPLIED (7 elements)
    if ($n >= 7 && $p[2] == 1 && _all_octets(@p[3..6])) {
        return (join('.', @p[3..6]), $p[1]);
    }
    # Format C: asNum.addrType(1).addrLen(4).b1.b2.b3.b4  no vpnId (7 elements)
    if ($n >= 7 && $p[1] == 1 && $p[2] == 4 && _all_octets(@p[3..6])) {
        return (join('.', @p[3..6]), $p[0]);
    }
    # Format D: asNum.addrType(1).b1.b2.b3.b4  IMPLIED no vpnId (6 elements)
    if ($n >= 6 && $p[1] == 1 && _all_octets(@p[2..5])) {
        return (join('.', @p[2..5]), $p[0]);
    }
    # Format E: IPv6 — vpnId.asNum.addrType(2).addrLen(16).16_bytes (20 elements)
    if ($n >= 20 && $p[2] == 2 && $p[3] == 16 && _all_octets(@p[4..19])) {
        my @b = @p[4..19];
        my $v6 = join(':', map { sprintf("%02x%02x", $b[$_*2], $b[$_*2+1]) } 0..7);
        return ($v6, $p[1]);
    }

    # Heuristic: scan for 4 consecutive octets (0-255) that form an IP
    for my $i (0 .. $n - 4) {
        next unless _all_octets(@p[$i..$i+3]);
        next if $p[$i] == 0 && $p[$i+1] == 0 && $p[$i+2] == 0 && $p[$i+3] == 0;
        my $addr = join('.', @p[$i..$i+3]);
        # AS number heuristic: skip addrType/addrLen markers
        my $as = '?';
        for (my $j = $i - 1; $j >= 0; $j--) {
            next if $p[$j] == 1 || $p[$j] == 4;  # skip addrType / addrLen
            $as = $p[$j]; last;
        }
        return ($addr, $as);
    }

    # Fallback — cannot extract IP; pick the best AS candidate.
    # For 3-element index (vpnId.asNum.addrType), AS is always $p[1].
    # EIGRP AS numbers are 1-65535; values above that are vpnId.
    my $as = '?';
    if ($n == 3) {
        $as = $p[1];
    } elsif ($n >= 2) {
        $as = ($p[0] > 65535) ? $p[1] : $p[0];
    } elsif ($n >= 1) {
        $as = $p[0];
    }
    return ($idx, $as);
}

sub _all_octets {
    for (@_) { return 0 unless defined $_ && /^\d+$/ && $_ >= 0 && $_ <= 255 }
    return 1;
}

sub usage {
    my $rc   = shift // UNKNOWN;
    my $name = basename($0);
    print <<"END_USAGE";
Usage: $name [OPTIONS]

 Checks BGP or EIGRP peers via SNMP.
 Auto-detects the routing protocol: tries BGP first, falls back to EIGRP.

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