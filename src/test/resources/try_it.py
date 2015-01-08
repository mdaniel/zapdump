from __future__ import print_function
import sys
from scrapy.contrib.downloadermiddleware.httpcompression import HttpCompressionMiddleware
from scrapy.contrib.httpcache import FilesystemCacheStorage
from scrapy.settings import Settings
from scrapy.http import Request


# no need for the full Spider class, it just asks its name for directory reasons
class Bob(object):
    name = None


def main(args):
    spider_name = args[0]
    url = args[1]
    spider = Bob()
    spider.name = spider_name
    settings = Settings()
    cache = FilesystemCacheStorage(settings)
    req = Request(url)
    raw_resp = cache.retrieve_response(spider, req)
    comp = HttpCompressionMiddleware()
    resp = comp.process_response(req, raw_resp, spider)
    print('Resp.class=%s' % type(resp))
    print('Resp=%s' % repr(resp))

if __name__ == '__main__':
    main(sys.argv[1:])
