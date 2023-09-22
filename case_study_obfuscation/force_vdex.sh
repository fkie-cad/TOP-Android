#!/bin/bash

# Based on: https://developer.android.com/topic/performance/baselineprofiles/manually-create-measure#androidx-profileinstaller

# Needs dependency in build.gradle:
# implementation("androidx.profileinstaller:profileinstaller:1.3.1") (or not...not sure yet)

PACKAGE_NAME="com.top.poctopobfuscation"

adb shell am broadcast -a androidx.profileinstaller.action.INSTALL_PROFILE ${PACKAGE_NAME}/androidx.profileinstaller.ProfileInstallerReceiver

adb shell am force-stop ${PACKAGE_NAME}

# Setup a baseline-prof.txt file in the same directory the AndroidManifest.xml file is in.
adb shell cmd package compile -f -m speed-profile ${PACKAGE_NAME}
