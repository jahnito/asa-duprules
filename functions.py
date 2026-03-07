import re
import sqlite3
import tomllib
from pathlib import Path

from patterns import UPPER_OBJ, UPPER_L3_PROTO, UPPER_L4_PROTO


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
        cursor.execute(queryes)
        conn.commit()


def init_app(config: str = 'asa_duprules.toml') -> dict:
    with open(config, 'rb') as f:
        cfg: dict = tomllib.load(f)
        # load rules to config var
        sh_access_list: str = cfg.get('dataset')
        with open(sh_access_list, 'r') as f:
            rules = f.read().split('\n')
            cfg['rules'] = rules
    init_database(cfg)
    return cfg


def define_rule(line: str, config):
    # Верхнеуровневое правило
    if line.startswith('access-list'):
        if re_match := re.fullmatch(UPPER_OBJ, line):
            ins_upper_obj(re_match, config)
            pass
        if re_match := re.fullmatch(UPPER_L3_PROTO, line):
            ins_upper_obj(re_match, config)
            pass
        if re_match := re.fullmatch(UPPER_L4_PROTO, line):
            ins_upper_obj(re_match, config)
            pass


def ins_upper_obj(re_match: re.Match, config: dict):
    finded_objects = {k: v for k, v in re_match.groupdict().items() if v is not None}

    # if config['debug']:
    #     elements = 0
    #     for key, value in finded_objects.items():
    #         print(elements + 1, key, ':', value)
    #         elements += 1
    #     input()
    
    database = config.get('database')
    query = (
        'INSERT INTO upper_rules ('
        f'{", ".join(finded_objects.keys())}'
        ') VALUES ('
        f'{"?, " * (len(finded_objects) - 1)} ?)'
    )

    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(finded_objects.values()))
        conn.commit()
