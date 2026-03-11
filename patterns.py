UPPER_OBJ = (
    r'^access-list\W(?P<zone>\S+)\sline\s'
    r'(?P<num_line>\d+)\sextended\s'
    r'(?P<rule>(?:permit|deny))\s(?:object-group\s'
    r'(?P<obj_gr_serv>\S+))\s(?:object-group\s'
    r'(?P<obj_gr_src>\S+)|host\s'
    r'(?P<host_src>(?:\d{1,3}\.){3}\d{1,3})|'
    r'(?P<any_src>any[4]?)|object\s'
    r'(?P<object_src>\S+)|'
    r'(?P<prefix_src>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3}))\s'
    r'(?:object-group\s(?P<obj_gr_dst>\S+)|host\s'
    r'(?P<host_dst>(?:\d{1,3}\.){3}\d{1,3})|'
    r'(?P<any_dst>any[4]?)|object\s'
    r'(?P<object_dst>\S+)|'
    r'(?P<prefix_dst>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3}))\s(?:'
    r'(?P<inactive>inactive)\s)?\(hitcnt=(?P<hit_count>\d+)\).+$'
)

UPPER_L3_PROTO = (
    r'^access-list\W(?P<zone>\S+)\sline\s'
    r'(?P<num_line>\d+)\sextended\s'
    r'(?P<rule>(?:permit|deny))\s'
    r'(?P<proto_l3>ip|icmp)\s(?:object-group\s'
    r'(?P<obj_gr_src>\S+)|host\s'
    r'(?P<host_src>(?:\d{1,3}\.){3}\d{1,3})|'
    r'(?P<any_src>any[4]?)|object\s'
    r'(?P<object_src>\S+)|'
    r'(?P<prefix_src>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3}))\s'
    r'(?:object-group\s(?P<obj_gr_dst>\S+)|host\s'
    r'(?P<host_dst>(?:\d{1,3}\.){3}\d{1,3})|'
    r'(?P<any_dst>any[4]?)|object\s'
    r'(?P<object_dst>\S+)|'
    r'(?P<prefix_dst>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3}))\s'
    r'(?:(?P<inactive>inactive)\s)?\(hitcnt=(?P<hit_count>\d+)\).+$'
)

UPPER_L4_PROTO = (
    r'^access-list\W(?P<zone>\S+)\sline\s'
    r'(?P<num_line>\d+)\sextended\s'
    r'(?P<rule>(?:permit|deny))\s'
    r'(?P<proto_l4>tcp|udp)\s(?:object-group\s'
    r'(?P<obj_gr_src>\S+)|host\s'
    r'(?P<host_src>(?:\d{1,3}\.){3}\d{1,3})|'
    r'(?P<any_src>any[4]?)|object\s'
    r'(?P<object_src>\S+)|'
    r'(?P<prefix_src>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3}))\s'
    r'(?:object-group\s'
    r'(?P<obj_gr_dst>\S+)|host\s'
    r'(?P<host_dst>(?:\d{1,3}\.){3}\d{1,3})|'
    r'(?P<any_dst>any[4]?)|object\s'
    r'(?P<object_dst>\S+)|'
    r'(?P<prefix_dst>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3}))\s'
    r'(?:object-group\s(?P<obj_gr_serv>\S+)|eq\s'
    r'(?P<proto_port>(?:\S+|\d+))|range\s'
    r'(?P<proto_ports>\d{1,5}\s\d{1,5}))\s(?:'
    r'(?P<inactive>inactive)\s)?\(hitcnt=(?P<hit_count>\d+)\).+$'
)


SUBRULE_L3 = (
    r'^\s{1,2}access-list\s(?P<zone>\S+)\sline\s(?P<num_line>\d+)\sextended\s(?P<rule>permit|deny)\s(?:(?P<proto_l3>ip|icmp)|(?P<proto_num>\d+))\s(?:host\s(?P<host_src>(?:\d{1,3}\.){3}\d{1,3})|(?P<prefix_src>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3})|(?P<any_src>(?:any|any4)))\s(?:host\s(?P<host_dst>(?:\d{1,3}\.){3}\d{1,3})|(?P<prefix_dst>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3})|(?P<any_dst>(?:any|any4)))(?:\s(?P<inactive>inactive))?\s\(hitcnt=(?P<hit_count>\d+)\).+$'
)

SUBRULE_L4 = (
    r'^\s{1,2}access-list\s(?P<zone>\S+)\sline\s(?P<num_line>\d+)\sextended\s(?P<rule>permit|deny)\s(?P<proto_l4>(tcp|udp))\s(?:host\s(?P<host_src>(?:\d{1,3}\.){3}\d{1,3})|(?P<prefix_src>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3})|(?P<any_src>(?:any|any4)))\s(?:host\s(?P<host_dst>(?:\d{1,3}\.){3}\d{1,3})|(?P<prefix_dst>(?:\d{1,3}\.){3}\d{1,3}\s(?:\d{1,3}\.){3}\d{1,3})|(?P<any_dst>(?:any|any4)))\s(?:eq\s(?P<proto_port>(?:\S+|\d+))|range\s(?P<proto_ports>(?:(?:\d{1,5}|\S+)\s(?:\d{1,5}|\S+))))(?:\s(?P<inactive>inactive))?\s\(hitcnt=(?P<hit_count>\d+)\).+$'
)


L3_PROTO_LITTER = {
    'citrix-ica': 1494,
    'domain': 53,
    'ftp': 21,
    'ftp-data': 20,
    'http': 80,
    'https': 443,
    'isakmp': 500,
    'ldap': 389,
    'ldaps': 636,
    'netbios-dgm': 138,
    'netbios-ns': 137,
    'netbios-ssn': 139,
    'ntp': 123,
    'pop3': 110,
    'rtsp': 554,
    'sip': 5060,
    'smtp': 25,
    'snmp': 161,
    'snmptrap': 162,
    'ssh': 22,
    'syslog': 514,
    'telnet': 23,
    'tftp': 69,
    'whois': 43,
    'www': 80,
}
