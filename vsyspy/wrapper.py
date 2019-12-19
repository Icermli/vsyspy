__copyright__ = "Copyright (C) 2019 Icerm"

__license__ = """
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

__doc__ = """
:mod:`vsyspy.wrapper` provides utilities for VSYS chain api.
"""

import os
import logging
import requests

from requests.exceptions import RequestException
from .errors import NetworkException


class Wrapper(object):
    """Class for VSYS chain api wrapper.
    """
    def __init__(self, node_host, api_key=''):
        self.node_host = node_host
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)

    def request(self, api, post_data=''):
        headers = {}
        url = os.path.join(self.node_host, api)
        if self.api_key:
            headers['api_key'] = self.api_key
        header_str = ' '.join(['--header \'{}: {}\''.format(k, v) for k, v in headers.items()])
        try:
            if post_data:
                headers['Content-Type'] = 'application/json'
                data_str = '-d {}'.format(post_data)
                self.logger.info("curl -X POST %s %s %s" % (header_str, data_str, url))
                return requests.post(url, data=post_data, headers=headers).json()
            else:
                self.logger.info("curl -X GET %s %s" % (header_str, url))
                return requests.get(url, headers=headers).json()
        except RequestException as ex:
            msg = 'Failed to get response: {}'.format(ex)
            raise NetworkException(msg)

