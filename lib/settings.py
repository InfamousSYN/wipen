#!/usr/bin/python3
import os

# Application Version
__version__ = "0.0.0.2"

# Directory Mapping
root_dir = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'wipen'))
log_dir = root_dir + "/log"
lib_dir = root_dir + "/lib"
