from . import AccountsApp

if __name__ == '__main__':
    accounts_app = AccountsApp()
    exit_code = accounts_app.run()
    exit(exit_code)
