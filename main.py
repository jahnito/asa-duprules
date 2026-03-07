from functions import define_rule, init_app

CFG = init_app()


if __name__ == '__main__':
    print(CFG.get('database'))
    print(CFG.get('dataset'))
    print(CFG.get('debug'))
    # result = 0
    for i in CFG['rules']:
        line = define_rule(i, CFG)
        if line:
            result += 1
