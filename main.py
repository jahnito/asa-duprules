from functions import main, init_app, create_rule_obj_l3

cfg = init_app()


if __name__ == '__main__':
    # main(config=CFG)
    create_rule_obj_l3(cfg)
