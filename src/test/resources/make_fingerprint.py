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
the_dir = sys.argv[2]
fh = open('%s/response_body' % the_dir, 'rb')
body = fh.read()
fh.close()
req = Request(the_url, body)
output = request_fingerprint(req)
print('output := %r' % output)
