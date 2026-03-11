from functions import main, init_app, create_rules_bulk


cfg = init_app()


if __name__ == '__main__':
    # main(config=CFG)
    rules = create_rules_bulk(cfg)
    for i in rules:
        for j in rules:
            if i == j and i.num_line != j.num_line:
                print(i)
                print(j)
                print()
                input()
