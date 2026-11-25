#!/usr/bin/env perl
# check_cisco_wlc_ha.pl - Nagios plugin for Cisco 9800 HA (SSO) health
# Adds --strict and --hard-strict modes for tighter alerting
# Author: M365 Copilot (for John Paul)
# License: MIT

use strict;
use warnings;
use Getopt::Long;
use Net::SNMP;

# --- OIDs ---
# CISCO-LWAPP-HA-MIB (use only when polling ACTIVE)
my $OID_cLHaPeerHotStandbyEvent = '1.3.6.1.4.1.9.9.843.1.3.4.0'; # 1=up, 0=down

# CISCO-RF-MIB (redundancy framework)
my $OID_cRFStatusUnitState       = '1.3.6.1.4.1.9.9.176.1.1.2.0';  # local unit state
my $OID_cRFStatusDuplexMode      = '1.3.6.1.4.1.9.9.176.1.1.6.0';  # 1=true(peer detected), 2=false
my $OID_cRFStatusPeerUnitState   = '1.3.6.1.4.1.9.9.176.1.1.4.0';  # peer unit state
my $OID_cRFStatusLastSwactReason = '1.3.6.1.4.1.9.9.176.1.1.8.0';  # last switchover reason

# CISCO-LWAPP-AP-MIB (IOS-XE 9800)
my $OID_cLApName         = '1.3.6.1.4.1.9.9.513.1.1.1.1.5';  # AP name (table)
my $OID_cLApSerialNumber = '1.3.6.1.4.1.9.9.513.1.1.1.1.17'; # AP serial number (table)

# AIRESPACE-WIRELESS-MIB (AireOS / 9800 compatibility MIBs — fallback)
my $OID_bsnAPName         = '1.3.6.1.4.1.14179.2.2.1.1.3';   # AP name
my $OID_bsnAPSerialNumber = '1.3.6.1.4.1.14179.2.2.1.1.17';  # AP serial number

# RFState map (subset)
my %RF_STATE = (
  1=>'notKnown', 2=>'disabled', 3=>'initialization', 4=>'negotiation',
  5=>'standbyCold', 9=>'standbyHot', 14=>'active', 17=>'standbyWarm'
);

# Switchover reasons (subset)
my %SWACT_REASON = (
  1=>'unsupported', 2=>'none', 3=>'notKnown', 4=>'userInitiated', 5=>'userForced',
  6=>'activeUnitFailed', 7=>'activeUnitRemoved', 8=>'activeGWdown', 9=>'activeRMIportdown'
);

# --- Options ---
my %opt = (
  host        => undef,
  version     => undef,
  community   => 'public',
  secname     => undef,
  seclevel    => undef,
  authproto   => 'SHA',
  authpass    => undef,
  privproto   => 'AES',
  privpass    => undef,
  timeout     => 15,
  port        => 161,
  verbose     => 0,
  strict      => 0,        # escalate unexpected states (peer-state mismatch, transitions) to CRITICAL
  hard_strict => 0,        # escalate ANY anomaly to CRITICAL (superset of --strict)
  ap_serial   => 0,        # also fetch and display all AP serial numbers
);

sub usage {
  my ($exit_code) = @_;
  print <<"USAGE";
Usage: $0 -H <host> [-p 1|2c|3] [-C <community>] [-P <port>] [-t <seconds>]
             [--username <user> --seclevel noAuthNoPriv|authNoPriv|authPriv
              --authprotocol SHA|MD5 --authpassword <pass>
              --privprotocol AES|AES128|DES|3DES|3DESDE --privpassword <pass>]
             [--contextengineid <hex>] [--contextname <name>]
             [-v] [--strict] [--hard-strict] [--ap-serial]

SNMP defaults to v2c, port 161 and a 15-second per-request timeout. Supplying
a username selects v3 unless a protocol is specified; the v3 security level
is inferred from the passwords unless --seclevel is given. Legacy --host, --version
<protocol>, --secname, --authproto, --authpass, --privproto and --privpass
remain available. SNMP_AUTHPW and SNMP_PRIVPW provide password fallbacks.
SNMPv3 shorthand: -C 'snmpv3,sha,authpass,aes,privpass,user[,engineid][,context]'
Use an empty engine ID to specify only a context name. -v may be repeated 3 times.
-?, --usage and -h, --help show help; -V, --version show plugin version.

Examples:
  $0 --host 172.26.9.68 --version 3 --secname nagios --authpass 'AuthPass' --privpass 'PrivPass' --timeout 10
  $0 --host 172.26.9.68 --version 2c --community '<community>' --timeout 10

Behavior:
  - Detects local unit role via CISCO-RF-MIB (active vs standbyHot).
  - If ACTIVE: checks HA peer reachability (cLHaPeerHotStandbyEvent) + RF duplex/peer state.
  - If STANDBYHOT: skips HA peer reachability (intended for active polling) and validates RF duplex & peer=ACTIVE.
  - Perfdata included for graphing trends.

Strict mode (--strict):
  - ACTIVE: peer_state != standbyHot  => CRITICAL
            peer_up = -1 (LWAPP-HA read failed) => CRITICAL
  - STANDBY HOT: peer_state != active => CRITICAL
  - Any branch: unexpected duplex code => CRITICAL
  - Transitional local states (neither active nor standbyHot) => CRITICAL

Hard strict (--hard-strict):
  - Includes all of --strict, plus:
  - ACTIVE: any peer_up value other than 1 (including -1, 0, or unexpected) => CRITICAL
  - Any branch: any unexpected value becomes CRITICAL (no UNKNOWN/WARN fallbacks)

AP serial numbers (--ap-serial):
  - Walks cLApTable (CISCO-LWAPP-AP-MIB) and appends each AP name + serial number to the
    output message. Useful for inventory and initial discovery.
USAGE
  ;
  exit(defined $exit_code ? $exit_code : 3);
}

Getopt::Long::Configure(qw(no_ignore_case bundling));
for (my $index = 0; $index < @ARGV; $index++) {
  if ($ARGV[$index] eq '--version' && ($index == $#ARGV || $ARGV[$index + 1] =~ /^-/)) {
    $ARGV[$index] = '--plugin-version';
  }
}
my ($help, $short_usage, $plugin_version);
GetOptions(
  'host|hostname|H=s' => \$opt{host},
  'version=s'     => \$opt{version},
  'protocol|p=s'  => \$opt{version},
  'community|C=s' => \$opt{community},
  'secname|username=s' => \$opt{secname},
  'seclevel=s'    => \$opt{seclevel},
  'authproto|authprotocol=s' => \$opt{authproto},
  'authpass|authpassword=s' => \$opt{authpass},
  'privproto|privprotocol=s' => \$opt{privproto},
  'privpass|privpassword=s' => \$opt{privpass},
  'contextengineid=s' => \$opt{contextengineid},
  'contextname=s' => \$opt{contextname},
  'timeout|t=i'   => \$opt{timeout},
  'port|P=i'      => \$opt{port},
  'verbose|v+'    => \$opt{verbose},
  'help|h'        => \$help,
  'usage|?'       => \$short_usage,
  'plugin-version|V' => \$plugin_version,
  'strict'        => \$opt{strict},
  'hard-strict'   => \$opt{hard_strict},
  'ap-serial'     => \$opt{ap_serial},
) or usage();
if ($plugin_version) { print "$0 1.0\n"; exit 0; }
if ($short_usage) { print "Usage: $0 -H <host> [-p 1|2c|3] [-C <community>] [SNMP options] [check options]\n"; exit 0; }
usage(0) if $help;
if (@ARGV) { print "UNKNOWN - Unexpected positional arguments\n"; exit 3; }
usage() unless $opt{host};

if ($opt{community} =~ /^snmpv3(.)/i) {
  my $separator = $1;
  my @fields = split /\Q$separator\E/, $opt{community}, -1;
  if (@fields < 6 || @fields > 8 || lc($fields[0]) ne 'snmpv3' || !$fields[2] || !$fields[4] || !$fields[5] ||
      (defined $opt{version} && $opt{version} ne '3') || defined $opt{secname} ||
      defined $opt{authpass} || defined $opt{privpass} ||
      (@fields > 6 && defined $opt{contextengineid}) || (@fields > 7 && defined $opt{contextname})) {
    print "UNKNOWN - Invalid or conflicting SNMPv3 community shorthand\n"; exit 3;
  }
  @opt{qw(authproto authpass privproto privpass secname)} = @fields[1..5];
  $opt{contextengineid} = $fields[6] if @fields > 6 && length $fields[6];
  $opt{contextname} = $fields[7] if @fields > 7 && length $fields[7];
  $opt{version} = '3';
} elsif ($opt{community} =~ /^snmpv3$/i) {
  print "UNKNOWN - Invalid SNMPv3 community shorthand\n"; exit 3;
}
$opt{version} //= defined $opt{secname} ? '3' : '2c';
$opt{authpass} //= $ENV{SNMP_AUTHPW};
$opt{privpass} //= $ENV{SNMP_PRIVPW};
if ($opt{port} < 1 || $opt{port} > 65535 || $opt{timeout} <= 0 || $opt{verbose} > 3) {
  print "UNKNOWN - Invalid port, timeout, or verbosity\n"; exit 3;
}
if (defined $opt{contextengineid}) {
  my $hex_engine = $opt{contextengineid};
  $hex_engine =~ s/^0x//i;
  if ($hex_engine !~ /\A[0-9a-f]{10,64}\z/i || length($hex_engine) % 2) {
    print "UNKNOWN - Context engine ID must be 5 to 32 bytes of hexadecimal\n"; exit 3;
  }
}
if (defined $opt{contextname} && length($opt{contextname}) > 32) {
  print "UNKNOWN - Context name must be at most 32 bytes\n"; exit 3;
}
if ($opt{version} ne '3' && (defined $opt{contextengineid} || defined $opt{contextname})) {
  print "UNKNOWN - SNMP context requires SNMPv3\n"; exit 3;
}
if ($opt{version} eq '3') {
  $opt{seclevel} //= $opt{privpass} ? 'authPriv' : $opt{authpass} ? 'authNoPriv' : 'noAuthNoPriv';
  if (!$opt{secname} || lc($opt{authproto}) !~ /\A(?:sha|md5)\z/ || lc($opt{privproto}) !~ /\A(?:aes|aes128|des|3des|3desde|3desede)\z/) {
    print "UNKNOWN - Invalid SNMPv3 username or protocol\n"; exit 3;
  }
  if (($opt{seclevel} eq 'authNoPriv' || $opt{seclevel} eq 'authPriv') && !$opt{authpass}) {
    print "UNKNOWN - SNMPv3 authentication password is required\n"; exit 3;
  }
  if ($opt{seclevel} eq 'authPriv' && !$opt{privpass}) {
    print "UNKNOWN - SNMPv3 privacy password is required\n"; exit 3;
  }
  $opt{privproto} = '3desede' if lc($opt{privproto}) eq '3desde';
} elsif (defined $opt{secname}) {
  print "UNKNOWN - --username requires SNMPv3\n"; exit 3;
}
print STDERR "SNMPv$opt{version} target=$opt{host} port=$opt{port} timeout=$opt{timeout}\n" if $opt{verbose};
print STDERR "SNMPv3 security=$opt{seclevel} auth=$opt{authproto} privacy=$opt{privproto}\n" if $opt{verbose} > 1 && $opt{version} eq '3';
print STDERR "SNMPv3 context name=".($opt{contextname} // '(default)')." engine=".($opt{contextengineid} // '(default)')."\n" if $opt{verbose} > 2 && $opt{version} eq '3';
my %context;
$context{-contextengineid} = $opt{contextengineid} if defined $opt{contextengineid};
$context{-contextname} = $opt{contextname} if defined $opt{contextname};

# Consolidated strict flag: true if --strict or --hard-strict is set
my $is_strict = ($opt{hard_strict} || $opt{strict}) ? 1 : 0;

# --- SNMP session ---
my ($session, $error);
if ($opt{version} eq '1' || $opt{version} eq '2c') {
  ($session, $error) = Net::SNMP->session(
    -hostname  => $opt{host},
    -community => $opt{community},
    -version   => $opt{version} eq '1' ? 1 : 2,
    -timeout   => $opt{timeout},
    -port      => $opt{port},
  );
} elsif ($opt{version} eq '3') {
  my %v3 = (
    -hostname  => $opt{host},
    -version   => 3,
    -username  => $opt{secname} // '',
    -timeout   => $opt{timeout},
    -port      => $opt{port},
  );
  if ($opt{seclevel} eq 'authNoPriv' || $opt{seclevel} eq 'authPriv') {
    $v3{-authprotocol} = lc $opt{authproto};
    $v3{-authpassword} = $opt{authpass} // '';
  } elsif ($opt{seclevel} ne 'noAuthNoPriv') {
    print "UNKNOWN - Unsupported SNMP security level '$opt{seclevel}'\n"; exit 3;
  }
  if ($opt{seclevel} eq 'authPriv') {
    $v3{-privprotocol} = lc $opt{privproto};
    $v3{-privpassword} = $opt{privpass} // '';
  }
  ($session, $error) = Net::SNMP->session(%v3);
} else {
  print "UNKNOWN - Unsupported SNMP version '$opt{version}'\n"; exit 3;
}
unless ($session) {
  print "UNKNOWN - SNMP session error: $error\n"; exit 3;
}

# --- Read RF states ---
my $rf = $session->get_request(
  -varbindlist => [ $OID_cRFStatusUnitState, $OID_cRFStatusDuplexMode, $OID_cRFStatusPeerUnitState, $OID_cRFStatusLastSwactReason ], %context
);
unless ($rf) {
  print "UNKNOWN - RF SNMP get failed: ".$session->error()."\n";
  $session->close(); exit 3;
}
my $unit_state  = $rf->{$OID_cRFStatusUnitState};
my $duplex_mode = $rf->{$OID_cRFStatusDuplexMode};
my $peer_state  = $rf->{$OID_cRFStatusPeerUnitState};
my $last_reason = $rf->{$OID_cRFStatusLastSwactReason};

my $unit_state_name = $RF_STATE{$unit_state} // "state_$unit_state";
my $peer_state_name = $RF_STATE{$peer_state} // "state_$peer_state";
my $reason_name     = $SWACT_REASON{$last_reason} // "reason_$last_reason";

my $is_active     = ($unit_state == 14) ? 1 : 0;
my $is_standbyhot = ($unit_state == 9)  ? 1 : 0;

# --- If active, read HA peer health ---
my $peer_up = undef;
if ($is_active) {
  my $ha = $session->get_request(-varbindlist => [ $OID_cLHaPeerHotStandbyEvent ], %context);
  if ($ha) {
    $peer_up = $ha->{$OID_cLHaPeerHotStandbyEvent};
  } else {
    $peer_up = -1; # read failed
  }
}

# --- AP Serial Numbers (optional) ---
my @ap_serial_msgs;
if ($opt{ap_serial}) {
  # Try CISCO-LWAPP-AP-MIB first; fall back to AIRESPACE-WIRELESS-MIB
  my $ap_serial_tbl = $session->get_table(-baseoid => $OID_cLApSerialNumber, %context);
  my ($serial_base, $name_base);
  if ($ap_serial_tbl && scalar keys %$ap_serial_tbl) {
    $serial_base = $OID_cLApSerialNumber;
    $name_base   = $OID_cLApName;
  } else {
    $ap_serial_tbl = $session->get_table(-baseoid => $OID_bsnAPSerialNumber, %context);
    if ($ap_serial_tbl && scalar keys %$ap_serial_tbl) {
      $serial_base = $OID_bsnAPSerialNumber;
      $name_base   = $OID_bsnAPName;
    }
  }
  if ($ap_serial_tbl && scalar keys %$ap_serial_tbl) {
    my $ap_name_tbl = $session->get_table(-baseoid => $name_base, %context);
    for my $oid (sort keys %$ap_serial_tbl) {
      (my $suffix = $oid) =~ s/^\Q$serial_base\E\.//;
      my $serial = $ap_serial_tbl->{$oid};
      my $name   = ($ap_name_tbl && defined $ap_name_tbl->{"$name_base.$suffix"})
                   ? $ap_name_tbl->{"$name_base.$suffix"}
                   : "AP[$suffix]";
      push @ap_serial_msgs, "$name=$serial";
    }
  } else {
    push @ap_serial_msgs, "AP serials unavailable (".$session->error().")";
  }
}
$session->close();

# --- Evaluate ---
my $status = 0; # OK
my @msgs;

if ($is_active) {
  push @msgs, "Role=ACTIVE($unit_state_name)";

  # HA peer reachability
  if (!defined $peer_up) {
    push @msgs, "HA Peer: unknown (LWAPP-HA read failed)";
    $status = $opt{hard_strict} ? 2 : ($is_strict ? 2 : (($status < 3) ? 3 : $status));
  } elsif ($peer_up == 1) {
    push @msgs, "HA Peer: reachable";
  } elsif ($peer_up == 0) {
    push @msgs, "HA Peer: DOWN";
    $status = 2; # CRITICAL
  } elsif ($peer_up == -1) {
    push @msgs, "HA Peer: unknown (LWAPP-HA read failed)";
    $status = $opt{hard_strict} ? 2 : ($is_strict ? 2 : (($status < 3) ? 3 : $status));
  } else {
    push @msgs, "HA Peer: unexpected=$peer_up";
    $status = $opt{hard_strict} ? 2 : (($status < 3) ? 3 : $status); # UNKNOWN unless hard-strict
  }

  # RF redundancy sanity
  if     ($duplex_mode == 1) { push @msgs, "RF: peer detected (duplex=true)"; }
  elsif  ($duplex_mode == 2) { push @msgs, "RF: peer NOT detected (duplex=false) -> possible RP/RMI issue"; $status = 2; }
  else                       { push @msgs, "RF: duplex unexpected=$duplex_mode"; $status = $is_strict ? 2 : (($status < 3) ? 3 : $status); }

  # Peer state expected standbyHot
  if ($peer_state == 9) { push @msgs, "RF PeerState: standbyHot"; }
  else { push @msgs, "RF PeerState: $peer_state_name (expected=standbyHot)"; $status = $is_strict ? 2 : ($status < 1 ? 1 : $status); }

} elsif ($is_standbyhot) {
  push @msgs, "Role=STANDBY($unit_state_name)";

  # RF duplex must be true, peer must be ACTIVE
  if     ($duplex_mode == 1) { push @msgs, "RF: peer detected (duplex=true)"; }
  elsif  ($duplex_mode == 2) { push @msgs, "RF: peer NOT detected (duplex=false) -> possible RP/RMI issue"; $status = 2; }
  else                       { push @msgs, "RF: duplex unexpected=$duplex_mode"; $status = $is_strict ? 2 : (($status < 3) ? 3 : $status); }

  if ($peer_state == 14) { push @msgs, "RF PeerState: active"; }
  else { push @msgs, "RF PeerState: $peer_state_name (expected=active)"; $status = $is_strict ? 2 : ($status < 1 ? 1 : $status); }

} else {
  # Transitional/abnormal states
  push @msgs, "Role=$unit_state_name";

  if     ($duplex_mode == 1) { push @msgs, "RF: peer detected (duplex=true)"; }
  elsif  ($duplex_mode == 2) { push @msgs, "RF: peer NOT detected (duplex=false)"; $status = 2; }
  else                       { push @msgs, "RF: duplex unexpected=$duplex_mode"; $status = $is_strict ? 2 : (($status < 3) ? 3 : $status); }

  push @msgs, "RF PeerState: $peer_state_name";
  # WARNING by default; CRITICAL under strict/hard-strict
  $status = $is_strict ? 2 : ($status < 1 ? 1 : $status);
}

# Add last switchover reason (informational)
push @msgs, "LastSwact: $reason_name";

# Add AP serial numbers (if requested)
if (@ap_serial_msgs) {
  push @msgs, "AP_Serials: ".join(", ", @ap_serial_msgs);
}

# --- Perfdata ---
my $peer_up_perf = defined $peer_up ? $peer_up : -1;
$peer_up_perf = -2 if $is_standbyhot; # not evaluated on standby
my @perf = (
  "peer_up=$peer_up_perf",
  "duplex=" . (($duplex_mode == 1) ? 1 : 0),
  "unit_state=$unit_state",
  "peer_state=$peer_state",
  "last_swact_reason=$last_reason"
);

# --- Output ---
my $prefix = $status==0 ? "OK" : $status==1 ? "WARNING" : $status==2 ? "CRITICAL" : "UNKNOWN";
print "$prefix - ".join("; ", @msgs)." | ".join(" ", @perf)."\n";
exit $status;

