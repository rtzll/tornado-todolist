import os

import tornado.web
import tornado.ioloop
import tornado.options
import tornado.httpserver

from tornado.options import define, options
define('port', default=8000, help='run on the given port', type=int)

BASEDIR = os.path.dirname(__file__)


class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', MainHandler),
            (r'/login', LoginHandler),
        ]
        settings = {
            'static_path':  os.path.join(BASEDIR, 'static'),
            'template_path': os.path.join(BASEDIR, 'templates'),
            'debug': True,
            'cookie_secret': os.environ.get('SECRET_KEY') or 'testing key',
        }
        super().__init__(handlers=handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    pass


class LoginHandler(BaseHandler):
    def get(self):
        self.render('login.html')


class MainHandler(BaseHandler):
    def get(self):
        self.write('ready for some to-do lists')


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()

if __name__ == '__main__':
    main()
