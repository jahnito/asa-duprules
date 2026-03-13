import re
import sqlite3
import tomllib
from pathlib import Path
from datetime import datetime

from classes import Rule
from patterns import UPPER_OBJ, UPPER_L3_PROTO, UPPER_L4_PROTO
from patterns import SUBRULE_L3, SUBRULE_L4
from patterns import OBJ_NET, OBJ_NET_HOST, OBJ_NET_SUBNET, OBJ_NET_DESCRIPTION


def init_database(config: dict):
    '''
    Функция инициализации БД
    '''
    if config['create_sql_dump']:
        queryset = Path(config.get('queryset_file'))
        if queryset.exists():
            confirm = input('File queryset exists, delete? [y|N]: ')
            if confirm.lower().startswith('y'):
                try:
                    queryset.unlink()
                except FileNotFoundError as e:
                    print(e)
                with open(config['queryset_file'], 'w') as f:
                    f.write(f'-- DATASET: {datetime.today()} --\n')
            else:
                config['queryset_memory'] = []
    else:
        # Создаем список для хранения селектов
        config['queryset_memory'] = []
    if config['init_db']:
        database = Path(config.get('database'))
        if database.exists():
            confirm = input('File db exists, delete? [y|N]: ')
            if confirm.lower().startswith('y'):
                try:
                    database.unlink()
                except FileNotFoundError as e:
                    print(e)

                print('Creating file db...')
                with sqlite3.connect(config['database']) as conn:
                    with open('sql/sql_execute_before.sql') as f:
                        queryes = f.read()
                    cursor = conn.cursor()
                    cursor.executescript(queryes)
                    conn.commit()
            else:
                print('db not create, use old data')
                config['init_db'] = False


def init_app(config: str = 'asa_duprules.toml') -> dict:
    '''
    Функция инициализации приложения
    читаем конфиг, подготавливаем БД
    '''
    with open(config, 'rb') as f:
        cfg: dict = tomllib.load(f)
        # load rules to config var
        sh_access_list: str = cfg.get('dataset')
        with open(sh_access_list, 'r') as f:
            rules = f.read().split('\n')
            cfg['rules'] = rules
    init_database(cfg)
    if cfg['init_db']:
        fill_db(cfg)
    return cfg


def define_rule(line: str, config):
    """
    Функция парсинга правил, создания INSERT-ов
    """
    if line.startswith('access-list'):
        if re_match := re.fullmatch(UPPER_OBJ, line):
            create_query(re_match, config, 'upper_rules')
        if re_match := re.fullmatch(UPPER_L3_PROTO, line):
            create_query(re_match, config, 'upper_rules')
        if re_match := re.fullmatch(UPPER_L4_PROTO, line):
            create_query(re_match, config, 'upper_rules')
    if line.startswith(' '):
        if re_match := re.fullmatch(SUBRULE_L3, line):
            create_query(re_match, config, 'rules')
        if re_match := re.fullmatch(SUBRULE_L4, line):
            create_query(re_match, config, 'rules')


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


def create_query(re_match: re.Match, config: dict, table: str):
    finded_objects = {k: v for k, v in re_match.groupdict().items() if v is not None}
    query = (
        f'INSERT INTO {table} ('
        f'{", ".join(finded_objects.keys())}'
        ') VALUES ("'
        f'{"\", \"".join(finded_objects.values())}'
        f'");'
    )
    if config['create_sql_dump']:
        with open(config['queryset_file'], 'a') as f:
            f.write(query + '\n')
    else:
        config['queryset_memory'].append(query)


def create_rules_bulk(config: dict):
    '''
    Создаем словарь с объектами правил
    '''
    rules = []
    database = config.get('database')
    # Запрос правил верхнего уровня без групповых объектов
    query_upper = (
                'SELECT * FROM upper_rules '
                'WHERE obj_gr_serv IS NULL AND '
                'obj_gr_src IS NULL AND '
                'object_src IS NULL AND '
                'obj_gr_dst IS NULL AND '
                'object_dst IS NULL;'
            )
    # Запрос правил нижнего уровня (групповых объектов в них нет)
    query_lower = 'SELECT * FROM rules;'

    for query in (query_upper, query_lower):
        with sqlite3.connect(database) as conn:
            cursor = conn.cursor()
            rows = cursor.execute(query)
            fields = [i[0] for i in cursor.description]
            for row in rows:
                raw_data = {k: v for k, v in zip(fields, row) if v is not None}
                rules.append(Rule(raw_data))
    return rules


def fill_db(config: dict):
    print('Fill database...')
    for line_rule in config['rules']:
        define_rule(line_rule, config)

    database = config.get('database')

    with sqlite3.connect(database) as conn:
        cursor = conn.cursor()
        if config['create_sql_dump']:
            with open(config['queryset_file']) as f:
                queryset = f.read()
            cursor.executescript(queryset)
        else:
            query = '\n'.join(config['queryset_memory'])
            cursor.executescript(query)
        conn.commit()


def parse_objects(line: str, parent_obj: dict|None):
    if re_match := re.fullmatch(OBJ_NET, line):
        return {re_match.group('obj_net'): []}
    if re_match := re.fullmatch(OBJ_NET_HOST, line):
        return parent_obj
    if re_match := re.fullmatch(OBJ_NET_SUBNET, line):
        return re_match, parent_obj
    if re_match := re.fullmatch(OBJ_NET_DESCRIPTION, line):
        return re_match, parent_obj

def create_objects(config: dict):
    # run_conf = config['run_conf']
    run_conf = 'sh_run.ios'
    with open(run_conf) as f:
        rc = f.read().split('\n')

    parent_obj = None
    for line in rc:
        if not line.startswith(' ') and parent_obj is not None:

        res = parse_objects(line, parent_obj)
        if res:
            parent_obj = res[1]
            print(res)
            input()
