from functions import init_app, create_rules_bulk


cfg = init_app()


if __name__ == '__main__':
    # if not cfg['create_sql_dump']:
    #     for i in cfg['queryset_memory']:
    #         print(i)
    #         input()
    pass




    # rules = create_rules_bulk(cfg)
    # num_items = len(rules)
    # eq_count = 0
    # for i in range(num_items):
    #     for j in range(i + 1, num_items):
    #         if rules[i] == rules[j] and rules[i].num_line != rules[j].num_line:
    #             print(rules[i])
    #             print('-' * 40)
    #             print(rules[j])
    #             print('*' * 40)
    #             eq_count += 1

    # print(f'Одинаковых правил {eq_count}')

    # eq_count = 0
    # for i in range(num_items):
    #     for j in range(i + 1, num_items):
    #         if rules[i] in rules[j] and rules[i].num_line != rules[j].num_line:
    #             print(rules[i])
    #             print('-' * 40)
    #             print(rules[j])
    #             print('*' * 40)
    #             eq_count += 1

    # print(f'Входящих правил {eq_count}')
