from functions import main, init_app, create_rules_bulk


cfg = init_app()


if __name__ == '__main__':
    # main(config=CFG)
    rules = create_rules_bulk(cfg)
    num_items = len(rules)
    eq_count = 0
    for i in range(num_items):
        for j in range(i + 1, num_items):
            if rules[i] == rules[j] and rules[i].num_line != rules[j].num_line:
                # print(rules[i])
                # print(rules[j])
                # print()
                # input()
                eq_count += 1

    print(eq_count)
