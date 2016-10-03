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
            tornado.web.url(r'/', MainHandler, name='main'),
            tornado.web.url(r'/register', RegisterHandler, name='register'),
            tornado.web.url(r'/login', LoginHandler, name='login'),
            tornado.web.url(r'/logout', LogoutHandler, name='logout'),
        ]
        settings = {
            'static_path':  os.path.join(BASEDIR, 'static'),
            'template_path': os.path.join(BASEDIR, 'templates'),
            'debug': True,
            'cookie_secret': os.environ.get('SECRET_KEY') or 'testing key',
            'xsrf_cookies': True,
        }
        super().__init__(handlers=handlers, **settings)


class BaseHandler(tornado.web.RequestHandler):
    pass


class RegisterHandler(BaseHandler):
    # TODO
    pass


class LoginHandler(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = tornado.escape.xhtml_escape(self.get_argument("username"))
        password = tornado.escape.xhtml_escape(self.get_argument("password"))
        # TODO replace when DB/User model is done
        if "demo" == username and "demo" == password:
            self.set_secure_cookie("user", self.get_argument("username"))
            self.redirect(self.get_argument('next', self.reverse_url('main')))
        self.render('login.html')


class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie('user')
        self.redirect(self.get_argument('next', self.reverse_url('main')))


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
