from dotenv import load_dotenv
import os
load_dotenv()

firebaseConfig = {
   'apiKey': os.getenv("FIREBASE_API_KEY"),
  'authDomain': os.getenv("FIREBASE_AUTHDOMAIN"),
    'databaseURL': os.getenv("FIREBASE_DATABASEURL"),
    'projectId': os.getenv("FIREBASE_PROJECTID"),
  'storageBucket': os.getenv("FIREBASE_STORAGEBUCKET"),
  'messagingSenderId': os.getenv("FIREBASE_MESSAGINSENDERID"),
  'appId': os.getenv("FIREBASE_APPID"),
  'measurementId': os.getenv("FIREBASE_MEASUREMENTID")
}