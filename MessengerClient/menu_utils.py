from getpass import getpass


class Menu:
    def __init__(self, client):
        self.client = client


    def item_text(self, base, value):
        if value:
            return f'{base}: {self.username}'
        return base
    

    def login(self):
        username = input('Enter username: ')
        password = getpass('Enter password: ')
        if username and password:
            success = self.client.login(username, password)
            if success:
                return True
            else:
                print('Login failed!')
                return False
        else:
            print('Invalid username or password!')
            return False
        

    def register(self):
        username = input('Enter username: ')
        password = getpass('Enter password: ')
        if username and password:
            success = self.client.register(username, password)
            if success:
                return True
            else:
                print('Register failed!')
                return False
        else:
            print('Invalid username or password!')
            return False
        

    def chat(self):
        while True:
            print('1. Show Chats')
            print('2. View Online Users')
            print('3. Logout')
            choice = input('Enter choice: ')
            if choice == '1':
                pass
            elif choice == '2':
                pass
            elif choice == '3':
                self.client.logout()
                break
            else:
                print('Invalid choice!')
            print()


    def show(self):
        # self.menu = ConsoleMenu('Home')

        # login_submenu = ConsoleMenu(title="Enter your credentials")
        # username_item = FunctionItem("Username", self.login_handler, ['username'])
        # password_item = FunctionItem("Password", self.login_handler, ['password'])
        # login_item = FunctionItem("Login", self.client.login, [self.username, self.password])
        # login_submenu.append_item(username_item)
        # login_submenu.append_item(password_item)
        # login_submenu.append_item(login_item)
        # login_submenu_item = SubmenuItem("Login", submenu=login_submenu)
        # login_submenu_item.set_menu(self.menu)
        # # register_item = FunctionItem("Register", self.client.register)

        # self.menu.append_item(login_submenu_item)
        # # self.menu.append_item(register_item)

        # self.menu.start()
        # self.menu.join()

        while True:
            print('1. Register')
            print('2. Login')
            print('3. Exit')
            choice = input('Enter choice: ')
            if choice == '1':
                success = self.register()
                if success:
                    self.chat()
            elif choice == '2':
                success = self.login()
                if success:
                    self.chat()
            elif choice == '3':
                break
            else:
                print('Invalid choice!')
            print()