import sys
import os

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from wsgiref.handlers import CGIHandler
   from vpn_server import app
   
   if __name__ == '__main__':
       CGIHandler().run(app)
   