from . import GasTankApp

if __name__ == '__main__':
    gas_tank_app = GasTankApp()
    exit_code = gas_tank_app.run()
    exit(exit_code)
