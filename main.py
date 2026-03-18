from functions import init_app, create_rules_bulk

from classes import Rule


cfg = init_app()


if __name__ == '__main__':
    rules :list[Rule] = create_rules_bulk(cfg)
    num_items = len(rules)
    eq_count = 0
    for i in range(num_items):
        for j in range(i + 1, num_items):
            if rules[i] == rules[j] and rules[i].num_line != rules[j].num_line:
                eq_count += 1
                print('\n\n', '*' * 20, f' Найдено полное совпадение правил ({eq_count})', '*' * 20, sep='')
                print('Rule A: ', rules[i].get_upper_rule(cfg), sep='\n')
                print(rules[i])
                print('-' * 40)
                print('Rule B: ', rules[j].get_upper_rule(cfg), sep='\n')
                print(rules[j])

    print('*' * 60)
    print(f'Одинаковых правил {eq_count}')
    print('*' * 60)

    in_count = 0
    for i in range(num_items):
        for j in range(i + 1, num_items):
            if rules[i] in rules[j] and rules[i].num_line != rules[j].num_line:
                eq_count += 1
                print('\n\n', '*' * 20, f' Найдено вхождение правила "A" в "B" ({in_count} )', '*' * 20, sep='')
                print('Rule A: ', rules[i].get_upper_rule(cfg), sep='\n')
                print(rules[i])
                print('-' * 40)
                print('Rule B: ', rules[j].get_upper_rule(cfg), sep='\n')
                print(rules[j])
    print('*' * 60)
    print(f'Входящих правил {eq_count}')
    print('*' * 60)
