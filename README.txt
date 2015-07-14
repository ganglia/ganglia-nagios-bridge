

ganglia-nagios-bridge


Copyright (C) 2010 Daniel Pocock
http://danielpocock.com/ganglia-nagios-bridge


Installation
------------

Copy ganglia-nagios-bridge.py to a suitable location (e.g. /usr/local/bin),
leaving off the '.py' extension.

Declare the services to be monitored in /etc/nagios3/*
  - see the included nagios.cfg for some examples

Copy nagios-bridge.conf to a suitable location (default /etc/ganglia)
and amend it as required.

Add ganglia-nagios-bridge to crontab
- it can be run every 1 to 5 minutes typically
- it must run as the nagios user so it will have permission to create files
  in the checkresult spool directory

e.g.

cat > /etc/crontab << EOF
# poll metrics from Ganglia, update Nagios
* * * * * nagios /usr/local/bin/ganglia-nagios-bridge
EOF

Limitations and troubleshooting
-------------------------------

Nagios must know about all the hosts and services exported by
Ganglia.  If it sees things in the checkresults file that it
doesn't know about, it logs warning messages about them
but it correctly processes all the things it does
recognise.

Make sure the hostnames and service names match exactly.

If the Ganglia XML is particularly large, you may want to buffer it
before parsing to avoid any risk of blocking the gmetad
while ganglia-nagios-bridge is working.  Of course, this requires
that you have sufficient RAM (or disk space) to buffer the XML.

Nagios is very picky about the checkresult filename.  mkstemp
is used to generate the filenames.  Nagios expects them to be
exactly 7 characters, starting with a 'c'.  Nagios will delete
the files after reading them.

Monitor nagios.log while it is processing the first checkresult
file to make sure it goes smoothly.  It will log errors if it
doesn't recognise a host or service name.  You may want to automatically
detect such issues in the log so that if new hosts/services appear in future,
you will be immediately alerted to update the Nagios configuration.


