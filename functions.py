import re
import sqlite3
import tomllib
from pathlib import Path
import ipaddress

from classes import Rule
from patterns import UPPER_OBJ, UPPER_L3_PROTO, UPPER_L4_PROTO
from patterns import SUBRULE_L3, SUBRULE_L4


def init_database(config: dict):
    database = Path(config.get('database'))
    if database.exists():
        confirm = input('File db exists, delete? [y|N]: ')
        if confirm.lower().startswith('y'):
            database.unlink()
        else:
            exit()
    print('Creating file db...')
    with sqlite3.connect(config['database']) as conn:
        with open('sql/sql_execute_before.sql') as f:
            queryes = f.read()
        cursor = conn.cursor()
        cursor.executescript(queryes)
        conn.commit()


def init_app(config: str = 'asa_duprules.toml') -> dict:
    with open(config, 'rb') as f:
        cfg: dict = tomllib.load(f)
        # load rules to config var
        sh_access_list: str = cfg.get('dataset')
        with open(sh_access_list, 'r') as f:
            rules = f.read().split('\n')
            cfg['rules'] = rules
    # init_database(cfg)
    return cfg


def define_rule(line: str, config):
    # Верхнеуровневое правило
    if line.startswith('access-list'):
        if re_match := re.fullmatch(UPPER_OBJ, line):
            ins_obj(re_match, config, 'upper_rules')
            pass
        if re_match := re.fullmatch(UPPER_L3_PROTO, line):
            ins_obj(re_match, config, 'upper_rules')
            pass
        if re_match := re.fullmatch(UPPER_L4_PROTO, line):
            ins_obj(re_match, config, 'upper_rules')
            pass
    if line.startswith(' '):
        if re_match := re.fullmatch(SUBRULE_L3, line):
            ins_obj(re_match, config, 'rules')
        if re_match := re.fullmatch(SUBRULE_L4, line):
            ins_obj(re_match, config, 'rules')


def ins_obj(re_match: re.Match, config: dict, table: str):
    finded_objects = {k: v for k, v in re_match.groupdict().items() if v is not None}
    database = config.get('database')
    query = (
        f'INSERT INTO {table} ('
        f'{", ".join(finded_objects.keys())}'
        ') VALUES ('
        f'{"?, " * (len(finded_objects) - 1)} ?)'
    )
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(finded_objects.values()))
        conn.commit()


def create_rule_obj_l3(config: dict):
    database = config.get('database')
    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        rows = cursor.execute('SELECT * FROM upper_rules WHERE obj_gr_serv IS NULL AND obj_gr_src IS NULL AND obj_gr_dst IS NULL;')
        fields = [i[0] for i in cursor.description]
        for row in rows:
            raw_data = {k: v for k, v in zip(fields, row) if v is not None}
            r = Rule(raw_data)
            print(r)
            input()


def main(config: dict):
    for line_rule in config['rules']:
        line = define_rule(line_rule, config)
        if line:
            result += 1
