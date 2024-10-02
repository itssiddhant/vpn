from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.uix.menu import MDDropdownMenu
from kivy.metrics import dp
from kivy.core.window import Window
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.boxlayout import MDBoxLayout
from kivy.properties import BooleanProperty
from vpn_client import login_user, send_encrypted_message_to_server,record_login
from register import  send_otp, verify_otp,register_user,db,hash_password

class LoginScreen(Screen):
    def toggle_password_visibility(self, instance_textfield):
        instance_textfield.password = not instance_textfield.password
        instance_textfield.icon_right = 'eye' if instance_textfield.password else 'eye-off'

    def on_touch_down(self, touch):
        
        password_field = self.ids.password
        
        if password_field.collide_point(*touch.pos):
            icon_pos_right = password_field.x + password_field.width - dp(48)  
            
            if touch.x > icon_pos_right:
                self.toggle_password_visibility(password_field)
                return True
        
        return super(LoginScreen, self).on_touch_down(touch)

class SignupScreen(Screen):
    def toggle_password_visibility(self, instance_textfield):
        instance_textfield.password = not instance_textfield.password
        instance_textfield.icon_right = 'eye' if instance_textfield.password else 'eye-off'

    def on_touch_down(self, touch):
        for field_id in ['signup_password', 'confirm_password']:
            password_field = self.ids[field_id]
            if password_field.collide_point(*touch.pos):
                icon_pos_right = password_field.x + password_field.width - dp(48)
                if touch.x > icon_pos_right:
                    self.toggle_password_visibility(password_field)
                    return True
        return super(SignupScreen, self).on_touch_down(touch)


class UsernameScreen(Screen):
    pass
class OTPScreen(Screen):
    pass

class ForgotPasswordScreen(Screen):
    def toggle_password_visibility(self, instance_textfield):
        instance_textfield.password = not instance_textfield.password
        instance_textfield.icon_right = 'eye' if instance_textfield.password else 'eye-off'

    def on_touch_down(self, touch):
        for field_id in ['new_password', 'confirm_password']:
            password_field = self.ids[field_id]
            if password_field.collide_point(*touch.pos):
                icon_pos_right = password_field.x + password_field.width - dp(48)
                if touch.x > icon_pos_right:
                    self.toggle_password_visibility(password_field)
                    return True
        return super(ForgotPasswordScreen, self).on_touch_down(touch)


class BlankScreen(Screen):
    vpn_active = BooleanProperty(False)  # Track VPN status
    

    def toggle_vpn(self):
        self.vpn_active = not self.vpn_active
        if self.vpn_active:
            self.ids.toggle_button.md_bg_color = (0, 0.5, 0, 1)  # Green when ON
            self.ids.vpn_status.text = "VPN is ON"
            self.ids.vpn_status.text_color = (0, 0.5, 0, 1)  # Green text color

            # Start sending encrypted message to the server
            message = "VPN connection established"
            send_encrypted_message_to_server(message)
        else:
            self.ids.toggle_button.md_bg_color = (0.5, 0, 0, 1)  # Red when OFF
            self.ids.vpn_status.text = "VPN is OFF"
            self.ids.vpn_status.text_color = (0.5, 0, 0, 1)  # Red text color
            
            # Send disconnection message
            message = "VPN connection terminated"
            send_encrypted_message_to_server(message)

class MyApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Gray"  # This is now valid
        self.theme_cls.accent_palette = "Teal"

        # Load KV files
        Builder.load_file('login.kv')
        Builder.load_file('signup.kv')
        Builder.load_file('otp.kv')
        Builder.load_file('forgot_password.kv')
        Builder.load_file('username.kv')
        Builder.load_file('blank.kv')
        

        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(SignupScreen(name='signup'))
        sm.add_widget(UsernameScreen(name='username'))
        sm.add_widget(OTPScreen(name='otp'))
        sm.add_widget(ForgotPasswordScreen(name='forgot_password'))
        sm.add_widget(BlankScreen(name='blank'))
        return sm
    
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_email = "Guest"
        self.user_password = None
        self.user_otp = None

    def login(self, email, password):
        hashed_password = hash_password(password)
        user_query = db.child("users").order_by_child("email").equal_to(email).get()
        if user_query.val():
            user_id = list(user_query.val().keys())[0]
            user_data = user_query.val()[user_id]
            if user_data['password'] == hashed_password:
                self.user_data = user_data
                self.user_data['localId'] = user_id
                record_login(user_id, email)
                self.root.current = 'blank'
                self.root.get_screen('blank').ids.profile_username.text = email
                # self.root.get_screen('blank').ids.organization_dropdown.text = user_data['organization']
                if user_data['role'].startswith('admin-'):
                    self.update_pending_requests()
                return True
        print("Login failed or user not approved")
        return False

    def enter_otp(self):
        otp = self.root.get_screen('otp').ids.otp_input.text
        if verify_otp(self.user_email, otp):
            print("OTP verified successfully")
            if register_user(self.user_email, self.user_password, self.user_organization):
                print("User registered successfully")
                self.root.current = 'login'
            else:
                print("Registration failed after OTP verification")
        else:
            print("OTP verification failed")

    def check_username(self, username):
        # Add your logic to check the username here
        # For example:
        if username == "":
            print("Username is empty.")
        else:
            print(f"Username entered: {username}")

    def signup(self, email, password, confirm_password, organization):
        if not email or not password or not confirm_password:
            print("All fields are required.")
            return
        
        if password == confirm_password:
            send_otp(email)
            self.user_email = email
            self.user_password = password
            self.user_organization = organization
            self.root.current = 'otp'
        else:
            print("Passwords do not match.")
    
    def show_signup_organization_menu(self, caller):
        menu_items = [
            {
                "viewclass": "OneLineListItem",
                "text": f"Organization {i}",
                "on_release": lambda x=f"Organization {i}": self.set_signup_organization(x, caller),
            } for i in range(1, 6)
        ]
        self.signup_organization_menu = MDDropdownMenu(
            caller=caller,
            items=menu_items,
            width_mult=4,
            max_height=Window.height * 0.5,
            background_color=self.theme_cls.bg_dark,
            radius=[15, 15, 15, 15],
            elevation=4,
        )
        self.signup_organization_menu.open()

    def set_signup_organization(self, organization_name, caller):
        caller.text = organization_name
        self.signup_organization_menu.dismiss()
            
    def change_screen(self, screen_name):
        self.root.current = screen_name

    def username_to_forgot_password(self):
        self.root.current = 'forgot_password'

    def apply_new_password(self, otp, new_password, confirm_password):
        # Placeholder for password reset logic
        if otp and new_password == confirm_password:
            print("Password reset successful")
            self.root.current = 'login'
        else:
            print("Password reset failed")
            # Show error message to user

    def show_country_menu(self, caller):
        menu_items = [
            {
                "viewclass": "OneLineListItem",
                "text": country,
                "on_release": lambda x=country: self.set_country(x, caller),
            } for country in ["India", "USA", "UK", "Canada", "Australia"]  # Add more countries as needed
        ]
        self.country_menu = MDDropdownMenu(
            caller=caller,
            items=menu_items,
            width_mult=4,
            max_height=Window.height * 0.5,
            background_color=self.theme_cls.primary_light,
        )
        self.country_menu.open()

    def set_country(self, country_name, caller):
        caller.text = country_name
        self.country_menu.dismiss()

    def show_organization_menu(self, caller):
        menu_items = [
        {
            "viewclass": "OneLineListItem",
            "text": f"Organization {i}",
            "on_release": lambda x=f"Organization {i}": self.set_organization(x, caller),
        } for i in range(1, 6)
    ]
        self.organization_menu = MDDropdownMenu(
            caller=caller,
            items=menu_items,
            width_mult=4,
            max_height=Window.height * 0.5,
            background_color=self.theme_cls.bg_dark,
            radius=[15, 15, 15, 15],
            elevation=4,
        )
        self.organization_menu.open()

    def set_organization(self, organization_name, caller):
        caller.text = organization_name
        self.organization_menu.dismiss()

    def show_role_menu(self, caller):
        menu_items = [
        {
            "viewclass": "OneLineListItem",
            "text": role,
            "on_release": lambda x=role: self.set_role(x, caller),
        } for role in ["Admin", "User", "Manager", "Developer"]
    ]
        self.role_menu = MDDropdownMenu(
            caller=caller,
            items=menu_items,
            width_mult=4,
            max_height=Window.height * 0.5,
            background_color=self.theme_cls.bg_dark,
            radius=[15, 15, 15, 15],
            elevation=4,
    )
        self.role_menu.open()

    def set_role(self, role_name, caller):
        caller.text = role_name
        self.role_menu.dismiss()

    def apply_profile_changes(self):
        blank_screen = self.root.get_screen('blank')
        username = blank_screen.ids.profile_username.text
        organization = blank_screen.ids.organization_dropdown.text
        role = blank_screen.ids.role_dropdown.text
        # Here you would typically save these changes to a database or file
        print(f"Applying changes: Username: {username}, Organization: {organization}, Role: {role}")
        
    def update_pending_requests(self):
        user_organization = self.user_data['organization']
        pending_requests = db.child("pending_approvals").child(user_organization).get().val()
        requests_list = self.root.get_screen('blank').ids.pending_requests_list
        requests_list.clear_widgets()

        if pending_requests and self.user_data['role'].startswith('admin-'):
            for key, request in pending_requests.items():
                card = MDCard(
                    size_hint_y=None,
                    height=dp(60),
                    md_bg_color=(0.3, 0.3, 0.3, 1),
                    padding=dp(10)
                )
                box = MDBoxLayout(orientation='horizontal', spacing=dp(10))
                label = MDLabel(
                    text=f"{request['email']} - {request['organization']}",
                    theme_text_color="Custom",
                    text_color=(1, 1, 1, 1),
                    size_hint_x=0.7
                )
                button = MDRaisedButton(
                    text='Approve',
                    size_hint_x=0.3,
                    md_bg_color=(0, 0.5, 0, 1),
                    on_release=lambda x, req=request, key=key: self.approve_request(req, key)
                )
                box.add_widget(label)
                box.add_widget(button)
                card.add_widget(box)
                requests_list.add_widget(card)

    def approve_request(self, request, key):
        user_organization = self.user_data['organization']
        db.child("users").child(request['user_id']).update({"role": f"user-{user_organization}"})
        db.child("pending_approvals").child(user_organization).child(key).remove()
        self.update_pending_requests()

    def toggle_vpn(self):
        blank_screen = self.root.get_screen('blank')
        if self.user_data['role'].startswith('user-'):
            blank_screen.vpn_active = not blank_screen.vpn_active
            if blank_screen.vpn_active:
                blank_screen.ids.toggle_button.md_bg_color = (0, 0.5, 0, 1)
                blank_screen.ids.vpn_status.text = "VPN is ON"
                blank_screen.ids.vpn_status.text_color = (0, 0.5, 0, 1)
            else:
                blank_screen.ids.toggle_button.md_bg_color = (0.5, 0, 0, 1)
                blank_screen.ids.vpn_status.text = "VPN is OFF"
                blank_screen.ids.vpn_status.text_color = (0.5, 0, 0, 1)
        else:
            print("You do not have permission to use VPN")


    def logout_button(self):
        self.root.current = 'login'
        print("Logout")

if __name__ == '__main__':
    MyApp().run()
    