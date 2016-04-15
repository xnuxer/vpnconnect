#!/usr/bin/perl -t

# VPNConnect --auth-user-pass-verify script.
# Only authenticate if username equals common_name.
# In VPNConnect.config file:
#   auth-user-pass-verify ./ucn.pl via-env

$username = $ENV{'username'};
$common_name = $ENV{'common_name'};

exit !(length($username) > 0 && length($common_name) > 0 && $username eq $common_name);
