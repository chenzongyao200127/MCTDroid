import os

#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#########################################################################################
#                          Imports  & Global Variables                                  #
#########################################################################################
# MobileSandbox Authentication Parameters
# MSURL = ''  # URL of the Mobile-Sandbox backend
# MSAPIFORMAT = 'json'
# MSAPIUSER = ''  # API user name
# MSAPIKEY = ''  # API key for the aforementioned user
# important files and folders
# TMPDIR = "/tmp/analysis/"
# AAPT = "aapt"
# AAPT = "/usr/local/bin/aapt"

AAPT = "/usr/bin/aapt"  # location of the aapt binary
# Get the current project directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

EMPTYICON = os.path.join(BASE_DIR, "empty.png")
APICALLS = os.path.join(BASE_DIR, "APIcalls.txt")
# location of the baksmali.jar file
BACKSMALI = os.path.join(BASE_DIR, "baksmali-2.0.3.jar")
ADSLIBS = os.path.join(BASE_DIR, "ads.csv")
