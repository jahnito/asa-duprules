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
                print('\n\n', '*' * 20, ' Найдено полное совпадение правил ', '*' * 20, sep='')
                print('Rule A: ', rules[i].get_upper_rule(cfg))
                print(rules[i])
                print('-' * 40)
                print('Rule B: ', rules[j].get_upper_rule(cfg))
                print(rules[j])
                eq_count += 1

    print('*' * 60)
    print(f'Одинаковых правил {eq_count}')
    print('*' * 60)

    eq_count = 0
    for i in range(num_items):
        for j in range(i + 1, num_items):
            if rules[i] in rules[j] and rules[i].num_line != rules[j].num_line:
                print('\n\n', '*' * 20, ' Найдено вхождение правила "A" в "B" ', '*' * 20, sep='')
                print('Rule A: ', rules[i].get_upper_rule(cfg))
                print(rules[i])
                print('-' * 40)
                print('Rule B: ', rules[j].get_upper_rule(cfg))
                print(rules[j])
                eq_count += 1
    print('*' * 60)
    print(f'Входящих правил {eq_count}')
    print('*' * 60)
