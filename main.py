from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.uix.menu import MDDropdownMenu
from kivy.metrics import dp
from kivy.core.window import Window
from kivymd.uix.card import MDCard
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.boxlayout import MDBoxLayout
from kivy.properties import BooleanProperty,ListProperty
from register import send_otp, verify_otp, register_user, hash_password, is_valid_email, is_strong_password
from vpn_client import record_login, send_encrypted_message_to_server,login_user,fetch_login_details, open_through_vpn 
from firebase_details import db, auth
from firebaseLog import FirebaseLogger
import sys

selected_encryption = 'AES' # globally declared

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
    last_login_details = ListProperty([])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.logger = None  # Initialize logger as None

    def on_pre_enter(self):
        # Get logger from app when screen is entered
        self.logger = MDApp.get_running_app().logger
        self.fetch_last_login_details()

    def fetch_last_login_details(self):
        app = MDApp.get_running_app()
        user_id = app.user_data['localId'] 
        login_details = fetch_login_details(user_id)    
        if login_details is None:
            login_details = [] 
        
        self.last_login_details = login_details
        
    def toggle_vpn(self):
        self.vpn_active = not self.vpn_active
        app = MDApp.get_running_app()

        if self.vpn_active:
            try:
                message = "VPN connection established"
                if app.id_token is not None:
                    success = send_encrypted_message_to_server(message, app.id_token, selected_encryption)
                    if success:
                        self.ids.toggle_button.md_bg_color = (0, 0.5, 0, 1)  # Green when ON
                        self.ids.vpn_status.text = "VPN is ON"
                        self.ids.vpn_status.text_color = (0, 0.5, 0, 1)  # Green text color
                        if self.logger:  # Check if logger exists before using
                            self.logger.log_activity('vpn_connect', 'VPN connection successful')
                        
                        # Modify this part to handle the web browser opening in a non-blocking way
                        from threading import Thread
                        def open_browser():
                            open_through_vpn("google.com", app.id_token)
                        Thread(target=open_browser, daemon=True).start()
                    else:
                        self.vpn_active = False
                        print("Failed to establish VPN connection.")
                else:
                    self.vpn_active = False
                    print("id_token is None, cannot toggle VPN")
            except Exception as e:
                print(f"Error in VPN toggle: {e}")
                self.vpn_active = False
                # Reset UI state on error
                self.ids.toggle_button.md_bg_color = (0.5, 0, 0, 1)
                self.ids.vpn_status.text = "VPN is OFF"
                self.ids.vpn_status.text_color = (0.5, 0, 0, 1)
                return
        else:
            try:
                message = "VPN connection terminated"
                send_encrypted_message_to_server(message, app.id_token, selected_encryption)
                self.ids.toggle_button.md_bg_color = (0.5, 0, 0, 1)  # Red when OFF
                self.ids.vpn_status.text = "VPN is OFF"
                self.ids.vpn_status.text_color = (0.5, 0, 0, 1)  # Red text color
                if self.logger:  # Check if logger exists before using
                    self.logger.log_activity('vpn_disconnect', 'VPN disconnection successful')
            except Exception as e:
                print(f"Error disconnecting VPN: {e}")

class MyApp(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "Gray" 
        self.theme_cls.accent_palette = "Teal"

        # Load KV files
        Builder.load_file('frontend/login.kv')
        Builder.load_file('frontend/signup.kv')
        Builder.load_file('frontend/otp.kv')
        Builder.load_file('frontend/forgot_password.kv')
        Builder.load_file('frontend/blank.kv')
        

        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(SignupScreen(name='signup'))
        sm.add_widget(OTPScreen(name='otp'))
        sm.add_widget(ForgotPasswordScreen(name='forgot_password'))
        sm.add_widget(BlankScreen(name='blank'))
        return sm
    
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.user_email = "Guest"
        self.user_password = None
        self.user_otp = None
        self.id_token= None
        self.logger = FirebaseLogger()
        
        sys.excepthook = self.handle_exception
    
    def handle_exception(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions"""
        self.logger.log_crash(exc_value)
        # You might want to show an error dialog to the user here
        
    
    def reset_login_fields(self):
        """Reset login screen fields"""
        login_screen = self.root.get_screen('login') 
        login_screen.ids.username.text = ''  # Reset username field
        login_screen.ids.password.text = ''

    def reset_signup_fields(self):
        """Reset signup screen fields"""
        signup_screen = self.root.get_screen('signup') 
        signup_screen.ids.signup_username.text = ""
        signup_screen.ids.signup_password.text = ""
        signup_screen.ids.confirm_password.text = ""
        signup_screen.ids.organization_dropdown.text = ""

    def reset_otp_field(self):
        """Reset OTP screen field"""
        otp_screen = self.root.get_screen('otp') 
        otp_screen.ids.otp_input.text = ""

    def reset_forgot_password_fields(self):
        """Reset forgot password screen fields"""
        forgot_password_screen = self.root.get_screen('forgot_password')
        forgot_password_screen.ids.email.text = ""
        forgot_password_screen.ids.otp.text = ""
        forgot_password_screen.ids.new_password.text = ""
        forgot_password_screen.ids.confirm_password.text = ""


    def login(self, email, password):
        try:
            user_id, user_data, id_token = login_user(email, password)
            
            if user_data and id_token:
                # Store the token for future API calls
                self.id_token = id_token
                
                # Store user data
                self.user_data = user_data
                self.user_data['localId'] = user_id
                
                self.logger.set_user_id(user_id)
                self.logger.log_login(email, success=True)
                
                # record_login(user_id, email)
                self.root.current = 'blank'
                self.root.get_screen('blank').ids.profile_username.text = email
                
                if user_data['role'].startswith('admin-'):
                    self.update_pending_requests()
                return True
            else:
                # Clear fields on failed login
                self.reset_login_fields()
                self.logger.log_login(email, success=False, 
                                    error_message="Invalid credentials")
                self.show_error_popup("Invalid email or password")
                return False
        except Exception as e:
            print(f"Login error: {e}")
            self.reset_login_fields()
            self.logger.log_login(email, success=False, 
                                error_message=str(e))
            self.show_error_popup(f"Login failed: {str(e)}")
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
    def show_error_popup(self, message):
        self.show_popup("Error", message, "error")

    def show_info_popup(self, message):
        self.show_popup("Information", message, "info")

    def show_popup(self, title, message, popup_type):
        if popup_type == "error":
            icon = "alert-circle-outline"
            icon_color = (1, 0, 0, 1)  # Red
        else:
            icon = "information-outline"
            icon_color = (0, 0.5, 0, 1)  # Green

        dialog = MDDialog(
            title=title,
            text=message,
            buttons=[
                MDFlatButton(
                    text="OK",
                    theme_text_color="Custom",
                    text_color=self.theme_cls.primary_color,
                    on_release=lambda x: dialog.dismiss()
                )
            ],
        )
        dialog.open()
    

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

    def show_country_menu(self, caller):
        menu_items = [
            {
                "viewclass": "OneLineListItem",
                "text": country,
                "on_release": lambda x=country: self.set_country(x, caller),
            } for country in ["India", "USA", "UK", "Canada", "Australia"]  
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
    
    def show_encryption_menu(self, caller):
        menu_items = [
            {
                "viewclass": "OneLineListItem",
                "text": encryption,
                "on_release": lambda x=encryption: self.set_encryption(x, caller),
            } for encryption in ["AES", "Blowfish", "ChaCha20"]
        ]
        self.encryption_menu = MDDropdownMenu(
            caller=caller,
            items=menu_items,
            width_mult=4,
            max_height=Window.height * 0.5,
            background_color=self.theme_cls.primary_light,
        )
        self.encryption_menu.open()

    def set_encryption(self, encryption_name, caller):
        caller.text = encryption_name
        self.encryption_menu.dismiss()
        selected_encryption = encryption_name  # Store in variable
        print(f"Selected encryption: {selected_encryption}")  # Print the variable

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

    def initiate_password_reset(self, email):
        if not is_valid_email(email):
            self.show_error_popup("Invalid email format")
            return

        try:
            user = auth.get_user_by_email(email)
            if send_otp(email):
                self.show_info_popup("OTP sent successfully. Please check your email and enter the OTP.")
                self.root.get_screen('forgot_password').ids.otp.disabled = False 
                self.root.get_screen('forgot_password').ids.new_password.disabled = True 
                self.root.get_screen('forgot_password').ids.confirm_password.disabled = True
                self.root.get_screen('forgot_password').ids.apply_button.disabled = True  
            else:
                self.show_error_popup("Failed to send OTP")
        except auth.UserNotFoundError:
            self.show_error_popup(f"No user found with email {email}")

    def verify_otp_and_enable_password_reset(self, email, otp):
        if not otp:
            self.show_error_popup("OTP is required")
            return

        if verify_otp(email, otp):
            self.show_info_popup("OTP verified. You can now enter a new password.")
            self.root.get_screen('forgot_password').ids.new_password.disabled = False  
            self.root.get_screen('forgot_password').ids.confirm_password.disabled = False
            self.root.get_screen('forgot_password').ids.apply_button.disabled = False  
        else:
            self.show_error_popup("Invalid OTP")

            
    def apply_new_password(self, email, new_password, confirm_password):
        if new_password != confirm_password:
            self.show_error_popup("Passwords do not match")
            return

        if not is_strong_password(new_password):
            self.show_error_popup("Password is not strong enough. It should be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
            return

        try:
            user = auth.get_user_by_email(email)
            hashed_password = hash_password(new_password)
            db.reference('users').child(user.uid).update({"password": hashed_password})
            self.show_info_popup("Password reset successful")
            self.root.current = 'login'
        except Exception as e:
            self.show_error_popup(f"Error resetting password: {e}")
        
    def update_pending_requests(self):
        user_organization = self.user_data['organization']
        pending_requests = db.reference('pending_approvals').child(user_organization).get()
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
        db.reference('users').child(request['user_id']).update({"role": f"user-{user_organization}"})
        db.reference('pending_approvals').child(user_organization).child(key).delete()
        self.update_pending_requests()


    def logout_button(self):
        if self.logger.user_id:
            self.logger.log_logout()
        self.root.current = 'login'
        self.id_token = None
        self.user_data = None
        self.logger.set_user_id(None)
        print("Logout")

if __name__ == '__main__':
    MyApp().run()
    