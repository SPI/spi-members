# -* coding: utf-8 -*-
"""
 SPI Members Web Application mod_wsgi driver script
"""

import os
import sys

os.environ['SPIAPP_CONFIG'] = '/srv/members.spi-inc.org/spiapp/spiapp.cfg'
sys.path.insert(0, '/usr/share/openstv')
sys.path.insert(0, '/srv/members.spi-inc.org/spiapp/')

from spiwebapp import app as application
