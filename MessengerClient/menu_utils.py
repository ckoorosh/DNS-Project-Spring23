from getpass import getpass
import os


class Menu:
    def __init__(self, client):
        self.client = client


    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')


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
        

    def show_chats(self):
        chats = self.client.show_chats()
        if not chats:
            print('No chats yet. Start messaging!')
            return
        print('-- Chats --')
        for chat in chats:
            print(f'{chat["username"]}: {chat["last_message"]}')
        print('----------')
        
    
    def send_chat_message(self):
        recipient = input('Enter recipient: ')
        message = input('Enter message: ')
        if recipient and message:
            success = self.client.send_chat_message(recipient, message)
            if success:
                print('Message sent!')
            else:
                print('Send message failed!')
        else:
            print('Invalid recipient or message!')
        

    def send_group_message(self):
        group = input('Enter group: ')
        message = input('Enter message: ')
        if group and message:
            success = self.client.send_group_message(group, message)
            if success:
                print('Message sent!')
            else:
                print('Send message failed!')
        else:
            print('Invalid group or message!')
        

    def view_chat(self):
        user = input('Enter user: ')
        if user:
            success, messages = self.client.view_chat(user)
            if success:
                self.clear()
                print(f'--- {user} ---')
                for message in messages:
                    print(f'{message["sender"]}: {message["message"]}')
                print('----------------------')
            else:
                print('View chat failed!')
        else:
            print('Invalid username!')


    def view_online_users(self):
        users = self.client.view_online_users()
        if not users:
            print('No online users!')
            return
        print('-- Online Users --')
        for i, user in enumerate(users):
            print(f'{i + 1}. {user}')
        print('-----------------')


    def show_group_chats(self):
        groups = self.client.show_group_chats()
        if not groups:
            print('No group chats yet. Create a group!')
            return
        print('-- Group Chats --')
        for group in groups:
            print(f'{group["name"]}: {group["last_message"]}')
        print('-----------------')


    def view_group_chat(self):
        group = input('Enter group: ')
        if group:
            success, messages = self.client.view_group_chat(group)
            if success:
                self.clear()
                print(f'Group {group}')
                print('----------------------')
                for message in messages:
                    print(f'{message["sender"]}: {message["message"]}')
                print('----------------------')
            else:
                print('View chat failed!')
        else:
            print('Invalid group!')
        

    def chat(self):
        while True:
            print('1. Show Chats')
            print('2. View Chat')
            print('3. View Online Users')
            print('4. Send Chat Message')
            print('5. Show Group Chats')
            print('6. View Group Chat')
            print('7. Send Group Message')
            print('0. Logout')
            choice = input('Enter choice: ')
            self.clear()
            if choice == '1':
                self.show_chats()
            if choice == '2':
                self.view_chat()
            elif choice == '3':
                self.view_online_users()
            elif choice == '4':
                self.send_chat_message()
            elif choice == '5':
                self.show_group_chats()
            elif choice == '6':
                self.view_group_chat()
            elif choice == '7':
                self.send_group_message()
            elif choice == '0':
                success = self.client.logout()
                if success:
                    break
                else:
                    print('Logout failed!')
            else:
                print('Invalid choice!')
            print()


    def show(self):
        while True:
            print('1. Register')
            print('2. Login')
            print('3. Exit')
            choice = input('Enter choice: ')
            self.clear()
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