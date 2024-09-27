from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.theming import ThemableBehavior
from kivymd.uix.menu import MDDropdownMenu
from kivy.metrics import dp
from kivy.core.window import Window
from kivymd.uix.button import MDFlatButton
from kivy.properties import BooleanProperty
from vpn_client import login_user, send_otp, verify_otp, encrypt_message, send_encrypted_message_to_server
from register import register_user

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
        
        password_field = self.ids.password
        
        if password_field.collide_point(*touch.pos):
            icon_pos_right = password_field.x + password_field.width - dp(48)  
            
            if touch.x > icon_pos_right:
                self.toggle_password_visibility(password_field)
                return True
        
        return super(LoginScreen, self).on_touch_down(touch)


class UsernameScreen(Screen):
    pass
class OTPScreen(Screen):
    pass

class ForgotPasswordScreen(Screen):
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


class BlankScreen(Screen):
    vpn_active = BooleanProperty(False)  # Track VPN status
    

    def toggle_vpn(self):
        self.vpn_active = not self.vpn_active
        if self.vpn_active:
            self.ids.toggle_button.md_bg_color = (0, 0.5, 0, 1)  # Green when ON
            self.ids.vpn_status.text = "VPN is ON"
            self.ids.vpn_status.text_color = (0, 0.5, 0, 1)  # Green text color

            # Start sending encrypted message to the server
            message = "This is a VPN test message"
            encrypted_message = encrypt_message(message)
            send_encrypted_message_to_server(encrypted_message)
        else:
            self.ids.toggle_button.md_bg_color = (0.5, 0, 0, 1)  # Red when OFF
            self.ids.vpn_status.text = "VPN is OFF"
            self.ids.vpn_status.text_color = (0.5, 0, 0, 1)  # Red text color

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

    def login(self, email, password):
        self.user_email = email
        token = login_user(email, password)  # Call login_user from vpn_client
        if token:
            send_otp(email, email, password)  # Send OTP using the email and password
            # otp = input("Enter the OTP sent to your email: ")  # Get OTP input
            self.root.current = 'otp'
            # if verify_otp(email, otp):  # Verify OTP
            #     self.root.current = 'blank'  # Redirect to the main VPN screen
            # else:
            #     print("OTP verification failed.")
        else:
            print("Login failed.")

    def enter_otp(self):
    # Add logic for OTP input
        otp = self.root.get_screen('otp').ids.otp_input.text
        if verify_otp(self.user_email, otp):
            self.root.current = 'blank'
            self.root.get_screen('blank').ids.profile_username.text = self.user_email  
        else:
            print("Invalid OTP")

    def check_username(self, username):
        # Add your logic to check the username here
        # For example:
        if username == "":
            print("Username is empty.")
        else:
            print(f"Username entered: {username}")

    def signup(self, email, password, confirm_password):
        if password == confirm_password:
            try:
                register_user(email, password)  # Register the user using register.py
                self.root.current = 'login'  # Redirect to login screen after successful signup
                print(f"User {email} registered successfully!")
            except Exception as e:
                print(f"Error during signup: {e}")
        else:
            print("Passwords do not match.")
            
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

if __name__ == '__main__':
    MyApp().run()