@echo off
title Build
pyinstaller -F main.py -i icon.ico --exclude-module matplotlib ^
                           --exclude-module scipy ^
                           --exclude-module setuptools ^
                           --exclude-module hook ^
                           --exclude-module distutils ^
                           --exclude-module site ^
                           --exclude-module hooks ^
                           --exclude-module tornado ^
                           --exclude-module PIL ^
                           --exclude-module PyQt4 ^
                           --exclude-module PyQt5 ^
                           --exclude-module pydoc ^
                           --exclude-module pythoncom ^
                           --exclude-module pytz ^
                           --exclude-module pywintypes ^
                           --exclude-module sqlite3 ^
                           --exclude-module pyz ^
                           --exclude-module pandas ^
                           --exclude-module sklearn ^
                           --exclude-module scapy ^
                           --exclude-module scrapy ^
                           --exclude-module sympy ^
                           --exclude-module kivy ^
                           --exclude-module pyramid ^
                           --exclude-module opencv ^
                           --exclude-module tensorflow ^
                           --exclude-module pipenv ^
                           --exclude-module pattern ^
                           --exclude-module mechanize ^
                           --exclude-module beautifulsoup4 ^
                           --exclude-module wxPython ^
                           --exclude-module pygi ^
                           --exclude-module pillow ^
                           --exclude-module pygame ^
                           --exclude-module pyglet ^
                           --exclude-module flask ^
                           --exclude-module django ^
                           --exclude-module pylint ^
                           --exclude-module pytube ^
                           --exclude-module odfpy ^
                           --exclude-module mccabe ^
                           --exclude-module pilkit ^
                           --exclude-module six ^
                           --exclude-module wrapt ^
                           --exclude-module astroid ^
                           --exclude-module isort
echo Build Sucessfull!
pause