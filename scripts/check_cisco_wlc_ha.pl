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
  version     => '3',      # prefer v3
  community   => 'public',
  secname     => undef,
  seclevel    => 'authPriv',
  authproto   => 'SHA',
  authpass    => undef,
  privproto   => 'AES',
  privpass    => undef,
  timeout     => 5,
  port        => 161,
  strict      => 0,        # escalate unexpected states (peer-state mismatch, transitions) to CRITICAL
  hard_strict => 0,        # escalate ANY anomaly to CRITICAL (superset of --strict)
  ap_serial   => 0,        # also fetch and display all AP serial numbers
);

sub usage {
  print <<"USAGE";
Usage: $0 --host <ip> [--version 2c|3] [--community <str>]
             [--secname <user> --seclevel noAuthNoPriv|authNoPriv|authPriv
              --authproto SHA|MD5 --authpass <pass>
              --privproto AES|DES --privpass <pass>]
             [--timeout <sec>] [--port 161] [--strict] [--hard-strict] [--ap-serial]

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
  exit 3;
}

GetOptions(
  'host=s'        => \$opt{host},
  'version=s'     => \$opt{version},
  'community=s'   => \$opt{community},
  'secname=s'     => \$opt{secname},
  'seclevel=s'    => \$opt{seclevel},
  'authproto=s'   => \$opt{authproto},
  'authpass=s'    => \$opt{authpass},
  'privproto=s'   => \$opt{privproto},
  'privpass=s'    => \$opt{privpass},
  'timeout=i'     => \$opt{timeout},
  'port=i'        => \$opt{port},
  'strict'        => \$opt{strict},
  'hard-strict'   => \$opt{hard_strict},
  'ap-serial'     => \$opt{ap_serial},
) or usage();
usage() unless $opt{host};

# Consolidated strict flag: true if --strict or --hard-strict is set
my $is_strict = ($opt{hard_strict} || $opt{strict}) ? 1 : 0;

# --- SNMP session ---
my ($session, $error);
if ($opt{version} eq '2c') {
  ($session, $error) = Net::SNMP->session(
    -hostname  => $opt{host},
    -community => $opt{community},
    -version   => 2,
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
  if ($opt{seclevel} eq 'noAuthNoPriv') {
    $v3{-security} = 'noAuthNoPriv';
  } elsif ($opt{seclevel} eq 'authNoPriv') {
    $v3{-security}     = 'authNoPriv';
    $v3{-authprotocol} = lc $opt{authproto};
    $v3{-authpassword} = $opt{authpass} // '';
  } else {
    $v3{-security}     = 'authPriv';
    $v3{-authprotocol} = lc $opt{authproto};
    $v3{-authpassword} = $opt{authpass} // '';
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
  -varbindlist => [ $OID_cRFStatusUnitState, $OID_cRFStatusDuplexMode, $OID_cRFStatusPeerUnitState, $OID_cRFStatusLastSwactReason ]
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
  my $ha = $session->get_request(-varbindlist => [ $OID_cLHaPeerHotStandbyEvent ]);
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
  my $ap_serial_tbl = $session->get_table(-baseoid => $OID_cLApSerialNumber);
  my ($serial_base, $name_base);
  if ($ap_serial_tbl && scalar keys %$ap_serial_tbl) {
    $serial_base = $OID_cLApSerialNumber;
    $name_base   = $OID_cLApName;
  } else {
    $ap_serial_tbl = $session->get_table(-baseoid => $OID_bsnAPSerialNumber);
    if ($ap_serial_tbl && scalar keys %$ap_serial_tbl) {
      $serial_base = $OID_bsnAPSerialNumber;
      $name_base   = $OID_bsnAPName;
    }
  }
  if ($ap_serial_tbl && scalar keys %$ap_serial_tbl) {
    my $ap_name_tbl = $session->get_table(-baseoid => $name_base);
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

