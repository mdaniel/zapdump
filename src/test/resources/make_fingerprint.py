import collections
import sys
from scrapy.utils.request import request_fingerprint
import scrapy.utils.request as __req
__req._fingerprint_cache = collections.defaultdict()


class Request(object):
    __slots__ = ['headers', 'method', 'url', 'body']
    def __init__(self, url, body):
        self.headers = dict()
        self.method = 'GET'
        self.url = url
        self.body = body

the_url = sys.argv[1]
body = ''
if len(sys.argv) > 2:
    the_dir = sys.argv[2]
    body_file = '%s/request_body' % the_dir
    if os.path.isfile(body_file):
        with open(body_file, 'rb') as fh:
            body = fh.read()
req = Request(the_url, body)
output = request_fingerprint(req)
print('output := %r' % output)
