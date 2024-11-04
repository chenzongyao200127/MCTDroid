#!/usr/bin/env python

"""
Mobile-Sandbox Static Analysis Settings

This module contains configuration settings for the Mobile-Sandbox static analysis tool.
Copyright (c) 2014, Mobile-Sandbox under GNU GPL v2+
"""

# Base paths
BASE_PATH = "/disk2/chenzy/MCTDroid/drebin-feature-extractor"

# Tool paths
AAPT = "/usr/bin/aapt"
BACKSMALI = f"{BASE_PATH}/baksmali-2.0.3.jar"

# Resource paths 
EMPTYICON = f"{BASE_PATH}/empty.png"
APICALLS = f"{BASE_PATH}/APIcalls.txt"
ADSLIBS = f"{BASE_PATH}/ads.csv"
