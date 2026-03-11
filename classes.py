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
            if port and port.isalpha():
                return L3_PROTO_LITTER[port]
            else:
                return int(port)

    def get_proto_ports(self):
        if line := self.raw_data.get('proto_ports'):
            return [
                L3_PROTO_LITTER['value'] if value.isalpha() else int(value) for value in line.split()
            ]

    def __str__(self):
        rule_line = (
            f'ID: {self.id}\n'
            f'ZONE: {self.zone}\n'
            f'RULE: {self.rule}\n'
            f'PROTO: {self.proto}\n'
            f'SOURCE: {self.src}\n'
            f'DESTIN: {self.dst}\n'
        )
        if self.port:
            rule_line += f'PORT: {self.port}'
        if self.ports:
            rule_line += f'PORTS: {' '.join(self.ports)}'
        return rule_line
