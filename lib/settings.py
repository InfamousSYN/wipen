#!/usr/bin/python3
import os

# Application Version
__version__ = "2.0.1"

# Directory Mapping
root_dir = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'wipen'))
log_dir = root_dir + "/log"
lib_dir = root_dir + "/lib"

# Parser Settings
BSSID_INSPECTION_DEPTH = 5
DEFAULT_IGNORED_BSSID = ['00:11:22:33:44:55', 'ff:ff:ff:ff:ff:ff']
DEFAULT_IGNORED_STA = ['00:11:22:33:44:00']

# General Settings
DEFAULT_PERIODIC_FILE_UPDATE_TIMER = 15
