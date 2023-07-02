import os
from getpass import getpass
from threading import Lock

from utils import Singleton

class Menu:
    def __init__(self, client):
        self.client = client
        self.buf = []
        self.lock = Lock()

    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def item_text(self, base, value):
        if value:
            return f'{base}: {self.username}'
        return base

    def login(self):
        username = self.get_input('Enter username: ')
        password = getpass('Enter password: ')
        if username and password:
            success = self.client.login(username, password)
            if success:
                return True
            else:
                self.add_to_buf('Login failed!')
                return False
        else:
            self.add_to_buf('Invalid username or password!')
            return False

    def register(self):
        name = self.get_input('Enter your name: ')
        username = self.get_input('Enter username: ')
        password = getpass('Enter password: ')
        if name and username and password:
            success = self.client.register(name, username, password)
            if success:
                return True
            else:
                self.add_to_buf('Register failed!')
                return False
        else:
            self.add_to_buf('Invalid username or password!')
            return False

    def show_chats(self):
        chats = self.client.show_chats()
        if not chats:
            self.add_to_buf('No chats yet. Start messaging!')
            return
        self.add_to_buf('-- Chats --')
        for chat in chats:
            self.add_to_buf(f'{chat}')
        self.add_to_buf('----------')

    def send_chat_message(self):
        message = self.get_input('Enter message: ')
        if not self.client.security_service.does_have_key(self.user):
            content, _ = self.client.send_message(
                self.client.base_url + '/sec/user_bundle_key/',
                {'username': self.user}
            )
            self.client.security_service.exchange_key(content, self.user, self.client.token, self.client.username)

        self.client.security_service.send_message_to_user(self.user, message, self.client.token)
        if self.user in self.client.chats:
            self.client.chats[self.user].append({'sender': self.client.username, 'message': message})
        else:
            self.client.chats[self.user] = [{'sender': self.client.username, 'message': message}]
        self.client.save_chat(self.user)

        # if recipient and message:
        #     success = self.client.send_chat_message(recipient, message)
        #     if success:
        #         self.add_to_buf('Message sent!')
        #     else:
        #         self.add_to_buf('Send message failed!')
        # else:
        #     self.add_to_buf('Invalid recipient or message!')

    def send_group_message(self):
        message = self.get_input('Enter message: ')
        if self.group and message:
            success = self.client.send_group_chat_message(self.group, message)
            if success:
                self.add_to_buf('Message sent!')
            else:
                self.add_to_buf('Send message failed!')
        else:
            self.add_to_buf('Invalid group or message!')

    def view_chat(self, update=False):
        if not update:
            user = self.get_input('Enter user: ')
        else:
            user = self.user
        if user:
            success, messages = self.client.view_chat(user)
            if success:
                self.clear()
                self.add_to_buf(f'--- {user} ---')
                for message in messages:
                    self.add_to_buf(f'{message["sender"]}: {message["message"]}')
                self.add_to_buf('----------------------')
                self.user = user
                return True
            else:
                self.add_to_buf('View chat failed!')
                return False
        else:
            self.add_to_buf('Invalid username!')
            return False

    def view_online_users(self):
        users = self.client.view_online_users()
        if not users:
            self.add_to_buf('No online users!')
            return
        self.add_to_buf('-- Online Users --')
        for i, user in enumerate(users):
            self.add_to_buf(f'{i + 1}. {user["name"]} ({user["username"]})')
        self.add_to_buf('-----------------')

    def show_group_chats(self):
        groups = self.client.show_group_chats()
        if not groups:
            self.add_to_buf('No group chats yet. Create a group!')
            return
        self.add_to_buf('-- Group Chats --')
        for group in groups:
            self.add_to_buf(f'{group["name"]} ({group["id"]}): {group["last_message"]}')
        self.add_to_buf('-----------------')

    def view_group_chat(self, update=False):
        if not update:
            group = self.get_input('Enter group: ')
        else:
            group = self.group
        if group:
            success, group_data = self.client.view_group_chat(group)
            if success:
                self.clear()
                # self.add_to_buf(f'Group {group_data["name"]({group})}')
                self.add_to_buf('----------------------')
                for message in group_data['messages']:
                    self.add_to_buf(f'{message["sender"]}: {message["message"]}')
                self.add_to_buf('----------------------')
                self.group = group
                return True
            else:
                self.add_to_buf('View group failed!')
                return False
        else:
            self.add_to_buf('Invalid group!')
            return False

    def create_group(self):
        group = self.get_input('Enter group name: ')
        if group:
            success = self.client.create_group(group)
            if success:
                self.add_to_buf('Group created!')
            else:
                self.add_to_buf('Create group failed!')
        else:
            self.add_to_buf('Invalid group!')

    def add_member_to_group(self):
        member = self.get_input('Enter member: ')
        if self.group and member:
            success = self.client.add_member_to_group(self.group, member)
            if success:
                self.add_to_buf('Member added!')
            else:
                self.add_to_buf('Add member failed! Check if the member is online or if you are the group admin.')
        else:
            self.add_to_buf('Invalid group or member!')

    def remove_member_from_group(self):
        member = self.get_input('Enter member: ')
        if self.group and member:
            success = self.client.remove_member_from_group(self.group, member)
            if success:
                self.add_to_buf('Member removed!')
            else:
                self.add_to_buf('Remove member failed! Check if the member is online or if you are the group admin.')
        else:
            self.add_to_buf('Invalid group or member!')

    def make_member_admin(self):
        member = self.get_input('Enter member: ')
        if self.group and member:
            success = self.client.make_member_admin(self.group, member)
            if success:
                self.add_to_buf('Member made admin!')
            else:
                self.add_to_buf('Make member admin failed! Check if you are the group admin.')
        else:
            self.add_to_buf('Invalid group or member!')

    def chat(self):
        while True:
            self.add_to_buf('1. Send Message')
            self.add_to_buf('2. View Messages')
            self.add_to_buf('0. Back')
            choice = self.get_input('Enter choice: ')
            self.clear()
            if choice == '1':
                self.send_chat_message()
            elif choice == '2':
                self.view_chat(update=True)
            elif choice == '0':
                self.user = None
                break
            else:
                self.add_to_buf('Invalid choice!')

    def group_chat(self):
        while True:
            self.add_to_buf('1. Send Message')
            self.add_to_buf('2. View Messages')
            self.add_to_buf('3. Add Member to Group')
            self.add_to_buf('4. Remove Member from Group')
            self.add_to_buf('5. Make Member Admin')
            self.add_to_buf('0. Back')
            choice = self.get_input('Enter choice: ')
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
                self.add_to_buf('Invalid choice!')

    def main(self):
        while True:
            self.add_to_buf('1. Show Chats')
            self.add_to_buf('2. View Chat')
            self.add_to_buf('3. View Online Users')
            self.add_to_buf('4. Show Group Chats')
            self.add_to_buf('5. View Group Chat')
            self.add_to_buf('6. Create Group')
            self.add_to_buf('0. Logout')
            choice = self.get_input('Enter choice: ')
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
                    self.add_to_buf('Logout failed!')
            else:
                self.add_to_buf('Invalid choice!')
            self.add_to_buf('')

    def show(self):
        while True:
            self.add_to_buf('1. Register')
            self.add_to_buf('2. Login')
            self.add_to_buf('3. Exit')
            choice = self.get_input('Enter choice: ')
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
                self.add_to_buf('Invalid choice!')
            self.add_to_buf('')

    def get_input(self, q=None) -> str:
        with self.lock:
            for t in self.buf:
                print(t)
            self.buf = []
        return input(q) if q else input()

    def add_to_buf(self, t):
        with self.lock:
            self.buf.append(t)
