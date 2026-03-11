import sqlite3
import ipaddress

from patterns import L3_PROTO_LITTER


class Rule:
    def __init__(self, raw_data: dict):
        self.raw_data: dict = raw_data
        self.id = self.get_id()
        self.zone = self.get_zone()
        self.num_line = self.get_num_line()
        self.rule = self.get_rule()
        self.proto: str = self.get_proto()
        self.src = self.get_src()
        self.dst = self.get_dst()
        self.port = self.get_proto_port()
        self.ports = self.get_proto_ports()

    def get_id(self):
        return self.raw_data['id']

    def get_zone(self):
        return self.raw_data['zone']

    def get_num_line(self):
        return int(self.raw_data['num_line'])

    def get_rule(self):
        return self.raw_data['rule']

    def get_proto(self) -> str:
        if proto := self.raw_data.get('proto_l3'):
            return proto
        if proto := self.raw_data.get('proto_num'):
            return proto
        else:
            return self.raw_data['proto_l4']

    def get_src(self):
        if src := self.raw_data.get('host_src'):
            return ipaddress.ip_address(src)
        elif src := self.raw_data.get('prefix_src'):
            return ipaddress.ip_network(src.replace(' ', '/'))
        elif src := self.raw_data.get('any_src'):
            return ipaddress.ip_network('0.0.0.0/0')

    def get_dst(self):
        if dst := self.raw_data.get('host_dst'):
            return ipaddress.ip_address(dst)
        elif dst := self.raw_data.get('prefix_dst'):
            return ipaddress.ip_network(dst.replace(' ', '/'))
        elif dst := self.raw_data.get('any_dst'):
            return ipaddress.ip_network('0.0.0.0/0')

    def get_proto_port(self):
        if port := self.raw_data.get('proto_port'):
            if port and not port.isdigit():
                return L3_PROTO_LITTER[port]
            else:
                return int(port)

    def get_proto_ports(self):
        if line := self.raw_data.get('proto_ports'):
            a, b = [
                L3_PROTO_LITTER[value] if value.isalpha() else int(value) for value in line.split()
            ]
            return range(a, b + 1)

    def __str__(self):
        if self.proto in ('tcp', 'udp',):
            rule_level = 'L4'
        else:
            rule_level = 'L3'
        rule_line = (
            f'Class <Rule> - {rule_level}\n'
            f'ID: {self.id}\n'
            f'ZONE: {self.zone} line {self.num_line}\n'
            f'RULE: {self.rule}\n'
            f'PROTO: {self.proto}\n'
            f'SOURCE: {self.src}\n'
            f'DESTIN: {self.dst}\n'
        )
        if self.port:
            rule_line += f'PORT: {self.port}'
        if self.ports:
            rule_line += f'PORTS: {' '.join([str(i) for i in self.ports])}'
        return rule_line

    def __eq__(self, other_rule):
        compare_attrs = [
                self.zone == other_rule.zone,
                self.rule == other_rule.rule,
                self.proto == other_rule.proto,
                self.src == other_rule.src,
                self.dst == other_rule.dst,
                self.port == other_rule.port,
            ]

        if self.port and other_rule.port:
            compare_attrs.append(self.proto == other_rule.proto)
        if self.ports and other_rule.ports:
            compare_attrs.append(self.ports == other_rule.ports)
        return all(compare_attrs)

