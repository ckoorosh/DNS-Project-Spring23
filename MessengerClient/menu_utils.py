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
        name = input('Enter your name: ')
        username = input('Enter username: ')
        password = getpass('Enter password: ')
        if name and username and password:
            success = self.client.register(name, username, password)
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
        message = input('Enter message: ')
        if self.group and message:
            success = self.client.send_group_message(self.group, message)
            if success:
                print('Message sent!')
            else:
                print('Send message failed!')
        else:
            print('Invalid group or message!')
        

    def view_chat(self, update=False):
        if not update:
            user = input('Enter user: ')
        else:
            user = self.user
        if user:
            success, messages = self.client.view_chat(user)
            if success:
                self.clear()
                print(f'--- {user} ---')
                for message in messages:
                    print(f'{message["sender"]}: {message["message"]}')
                print('----------------------')
                self.user = user
                return True
            else:
                print('View chat failed!')
                return False
        else:
            print('Invalid username!')
            return False
        

    def confirm_session(self):
        if self.user:
            content = self.client.confirm_session(self.user)
            if content:
                print(content)


    def view_online_users(self):
        users = self.client.view_online_users()
        if not users:
            print('No online users!')
            return
        print('-- Online Users --')
        for i, user in enumerate(users):
            print(f'{i + 1}. {user["name"]} ({user["username"]})')
        print('-----------------')


    def show_group_chats(self):
        groups = self.client.show_group_chats()
        if not groups:
            print('No group chats yet. Create a group!')
            return
        print('-- Group Chats --')
        for group in groups:
            print(f'{group["name"]} ({group["id"]}): {group["last_message"]}')
        print('-----------------')


    def view_group_chat(self, update=False):
        if not update:
            group = input('Enter group: ')
        else:
            group = self.group
        if group:
            success, group_data = self.client.view_group_chat(group)
            if success:
                self.clear()
                print(f'Group {group_data["name"] ({group})}')
                print('----------------------')
                for message in group_data['messages']:
                    print(f'{message["sender"]}: {message["message"]}')
                print('----------------------')
                self.group = group
                return True
            else:
                print('View group failed!')
                return False
        else:
            print('Invalid group!')
            return False


    def create_group(self):
        group = input('Enter group name: ')
        if group:
            success = self.client.create_group(group)
            if success:
                print('Group created!')
            else:
                print('Create group failed!')
        else:
            print('Invalid group!')


    def add_member_to_group(self):
        member = input('Enter member: ')
        if self.group and member:
            success = self.client.add_member_to_group(self.group, member)
            if success:
                print('Member added!')
            else:
                print('Add member failed! Check if the member is online or if you are the group admin.')
        else:
            print('Invalid group or member!')


    def remove_member_from_group(self):
        member = input('Enter member: ')
        if self.group and member:
            success = self.client.remove_member_from_group(self.group, member)
            if success:
                print('Member removed!')
            else:
                print('Remove member failed! Check if the member is online or if you are the group admin.')
        else:
            print('Invalid group or member!')

    
    def make_member_admin(self):
        member = input('Enter member: ')
        if self.group and member:
            success = self.client.make_member_admin(self.group, member)
            if success:
                print('Member made admin!')
            else:
                print('Make member admin failed! Check if you are the group admin.')
        else:
            print('Invalid group or member!')


    def chat(self):
        while True:
            print('1. Send Message')
            print('2. View Messages')
            print('3. Confirm Session')
            print('0. Back')
            choice = input('Enter choice: ')
            self.clear()
            if choice == '1':
                self.send_chat_message()
            elif choice == '2':
                self.view_chat(update=True)
            elif choice == '3':
                self.confirm_session()
            elif choice == '0':
                self.user = None
                break
            else:
                print('Invalid choice!')

    
    def group_chat(self):
        while True:
            print('1. Send Message')
            print('2. View Messages')
            print('3. Add Member to Group')
            print('4. Remove Member from Group')
            print('5. Make Member Admin')
            print('0. Back')
            choice = input('Enter choice: ')
            self.clear()
            if choice == '1':
                self.send_group_message()
            if choice == '2':
                self.view_group_chat(update=True)
            elif choice == '3':
                self.add_member_to_group()
            elif choice == '4':
                self.remove_member_from_group()
            elif choice == '5':
                self.make_member_admin()
            elif choice == '0':
                self.group = None
                break
            else:
                print('Invalid choice!')
        

    def main(self):
        while True:
            print('1. Show Chats')
            print('2. View Chat')
            print('3. View Online Users')
            print('4. Show Group Chats')
            print('5. View Group Chat')
            print('6. Create Group')
            print('0. Logout')
            choice = input('Enter choice: ')
            self.clear()
            if choice == '1':
                self.show_chats()
            if choice == '2':
                success = self.view_chat()
                if success:
                    self.chat()
            elif choice == '3':
                self.view_online_users()
            elif choice == '4':
                self.show_group_chats()
            elif choice == '5':
                success = self.view_group_chat()
                if success:
                    self.group_chat()
            elif choice == '6':
                self.create_group()
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
                    self.main()
            elif choice == '2':
                success = self.login()
                if success:
                    self.main()
            elif choice == '3':
                break
            else:
                print('Invalid choice!')
            print()