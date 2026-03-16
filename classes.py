import ipaddress
import sqlite3
import re

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

    def get_upper_rule(self, config: dict) -> str:
        query = (
            'SELECT original_line FROM upper_rules '
            f'WHERE zone="{self.zone}" and num_line={self.num_line};'
        )
        with sqlite3.connect(config['database']) as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            result = cursor.fetchone()
        pattern = r'line\s\d+\s|\s\(hitcnt=\d+\)\s.+'
        return re.sub(pattern, '', result[0])

    def get_upper_objects(self):
        query = (
            'SELECT obj_gr_src, host_src, object_scr, prefix_src, '
            '       obj_gr_src, host_src, object_scr, prefix_src, '
            f'FROM upper_rules WHERE zone="{self.zone}" and num_line={self.num_line}'
        )

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
            rule_line += f'PORTS: {min(self.ports)}-{max(self.ports)}'
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
            compare_attrs.append(self.port == other_rule.port)
        if self.ports and other_rule.ports:
            compare_attrs.append(self.ports == other_rule.ports)
        return all(compare_attrs)

    def __contains__(self, other_rule):
        # Если правила равны, то возвращаем False
        if self == other_rule:
            return False
        # Обязательные атрибуты которые должны быть равны
        compare_attrs = [
            self.zone == other_rule.zone,
            self.rule == other_rule.rule,
            self.proto == other_rule.proto,
        ]

        # Проверка вхождения источника
        # Адрес в адрес
        if (
            isinstance(self.src, ipaddress.IPv4Address)
            and
            isinstance(other_rule.src, ipaddress.IPv4Address)
        ):
            compare_attrs.append(
                self.src == other_rule.src
            )
        # Адрес в подсеть
        elif (
            isinstance(other_rule.src, ipaddress.IPv4Address)
            and
            isinstance(self.src, ipaddress.IPv4Network)
        ):
            compare_attrs.append(
                other_rule.src in self.src
            )
        # Сеть в сеть
        elif (
            isinstance(other_rule.src, ipaddress.IPv4Network)
            and
            isinstance(self.src, ipaddress.IPv4Network)
        ):
            compare_attrs.append(
                (
                    other_rule.src.network_address in self.src
                    and
                    other_rule.src.broadcast_address in self.src
                )
            )
        elif (
            isinstance(other_rule.src, ipaddress.IPv4Network)
            and
            isinstance(self.src, ipaddress.IPv4Address)
        ):
            return False

        # Проверка вхождения назначения
        # Адрес в адрес
        if (
            isinstance(self.dst, ipaddress.IPv4Address)
            and
            isinstance(other_rule.dst, ipaddress.IPv4Address)
        ):
            compare_attrs.append(
                self.dst == other_rule.dst
            )
        # Адрес в подсеть
        elif (
            isinstance(other_rule.dst, ipaddress.IPv4Address)
            and
            isinstance(self.dst, ipaddress.IPv4Network)
        ):
            compare_attrs.append(
                other_rule.dst in self.dst
            )
        # Сеть в сеть
        elif (
            isinstance(other_rule.dst, ipaddress.IPv4Network)
            and
            isinstance(self.dst, ipaddress.IPv4Network)
        ):
            compare_attrs.append(
                (
                    other_rule.dst.network_address in self.dst
                    and
                    other_rule.dst.broadcast_address in self.dst
                )
            )
        elif (
            isinstance(other_rule.dst, ipaddress.IPv4Network)
            and
            isinstance(self.dst, ipaddress.IPv4Address)
        ):
            return False

        # Вхождение портов
        # Порт в порт
        if self.port and other_rule.port:
            compare_attrs.append(
                self.port == other_rule.port
            )
        # Порт в диапозон портов
        elif other_rule.port and self.ports:
            compare_attrs.append(
                other_rule.port in self.ports
            )
        # Диапазон в диапазон
        elif other_rule.ports and self.ports:
            compare_attrs.append(
                min(other_rule.ports) in self.ports
                and
                max(other_rule.ports) in self.ports
            )
        # Дипазон в один порт не может входить
        elif other_rule.ports and self.port:
            return False

        return all(compare_attrs)


class ObjectNetwork:
    def __init__(self, name: str, type_obj: str) -> None:
        self.name = name
        self.type_obj = type_obj
        self.obj_gr_host = []
        self.obj_gr_obj = []
        self.obj_gr_obj_gr = []
        self.obj_gr_subnet = []
        self.obj_net_host = []
        self.obj_net_subnet = []
        self.description = None

    def get_attrs(self, attrs: dict) -> None:
        for k, v in attrs.items():
            if v:
                if k == 'description':
                    self.description = v
                if k == 'obj_gr_host':
                    self.obj_gr_host.append(v)
                if k == 'obj_gr_obj':
                    self.obj_gr_obj.append(v)
                if k == 'obj_gr_obj_gr':
                    self.obj_gr_obj_gr.append(v)
                if k == 'obj_gr_subnet':
                    self.obj_gr_subnet.append(v)
                if k == 'obj_net_host':
                    self.obj_net_host.append(v)
                if k == 'obj_net_subnet':
                    self.obj_net_subnet.append(v)

    def _make_list_attrs(self):
        return [
                self.obj_net_host,
                self.obj_net_subnet,
                self.obj_gr_host,
                self.obj_gr_subnet,
                self.obj_gr_obj,
                self.obj_gr_obj_gr
            ]

    def create_dump(self):
        result = [
            (
                'INSERT INTO asa_objects (name, obj_type, description) '
                f'VALUES ("{self.name}", "{self.type_obj}",'
                f' {'"' + self.description + '"' if self.description else 'NULL'});'
            )
        ]
        if self.type_obj == 'obj_net':
            if self.obj_net_host:
                result.append(
                    'INSERT INTO asa_obj_hosts (`host`, asa_object) VALUES '
                    f'("{self.obj_net_host[0]}", (SELECT id FROM asa_objects WHERE name="{self.name}"));'
                )
            if self.obj_net_subnet:
                result.append(
                    'INSERT INTO asa_obj_subnets (`subnet`, asa_object) VALUES '
                    f'("{self.obj_net_subnet[0]}", (SELECT id FROM asa_objects WHERE name="{self.name}"));'
                )
        if self.type_obj == 'obj_gr_net':
            if self.obj_gr_host:
                for host in self.obj_gr_host:
                    result.append(
                        'INSERT INTO asa_obj_hosts (`host`, asa_object) '
                        f'VALUES ("{host}", (SELECT id FROM asa_objects WHERE name="{self.name}"));'
                    )
            if self.obj_gr_subnet:
                for subnet in self.obj_gr_subnet:
                    result.append(
                        'INSERT INTO asa_obj_subnets (`subnet`, asa_object) '
                        f'VALUES ("{subnet}", (SELECT id FROM asa_objects WHERE name="{self.name}"));'
                    )
            if self.obj_gr_obj:
                for obj in self.obj_gr_obj:
                    result.append(
                        'INSERT INTO asa_obj_objects (`object`, asa_object) '
                        f'VALUES ("{obj}", (SELECT id FROM asa_objects WHERE name="{self.name}"));'
                    )
            if self.obj_gr_obj_gr:
                for group in self.obj_gr_obj_gr:
                    result.append(
                        'INSERT INTO asa_obj_groups (`group`, asa_object) '
                        f'VALUES ("{group}", (SELECT id FROM asa_objects WHERE name="{self.name}"));'
                    )
        return '\n'.join(result)

    def __str__(self):
        line = f'Object <{self.name}> type <{self.type_obj}>'
        if self.obj_net_host:
            line += f'\nhost: {'\n  '.join(self.obj_net_host)}'
        if self.obj_net_subnet:
            line += f'\nsubnet: {'\n  '.join(self.obj_net_subnet)}'
        if self.obj_gr_host:
            line += f'\nhosts:\n  {'\n  '.join(self.obj_gr_host)}'
        if self.obj_gr_subnet:
            line += f'\nsubnets:\n  {'\n  '.join(self.obj_gr_subnet)}'
        if self.obj_gr_obj:
            line += f'\nobjects:\n  {'\n  '.join(self.obj_gr_obj)}'
        if self.obj_gr_obj_gr:
            line += f'\nobj_groups:\n  {'\n  '.join(self.obj_gr_obj_gr)}'
        return line

    def __bool__(self):
        return any(self._make_list_attrs())
