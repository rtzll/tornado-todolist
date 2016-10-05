import os
import concurrent.futures

import motor
import bcrypt
import tornado.web
import tornado.ioloop
import tornado.options
import tornado.httpserver

from tornado.options import define, options
define('port', default=8000, help='run on the given port', type=int)

BASEDIR = os.path.dirname(__file__)

# A thread pool to be used for password hashing with bcrypt.
bcrypt_executor = concurrent.futures.ThreadPoolExecutor(2)


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

        self.db = motor.motor_tornado.MotorClient()


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db


class RegisterHandler(BaseHandler):
    # TODO
    pass


class LoginHandler(BaseHandler):
    def get(self):
        self.render('login.html')

    async def post(self):
        email_or_username = tornado.escape.xhtml_escape(
            self.get_argument('email_or_username'))
        user = await self.db.users.find_one({'$or': [
            {'email': email_or_username},
            {'username': email_or_username},
        ]})
        if user and await self.check_password(user):
            self.set_secure_cookie('user', self.get_argument('username'))
            self.redirect(self.get_argument('next', self.reverse_url('main')))
        # TODO indicate failure
        self.render('login.html')

    async def check_password(self, user):
        hashed_password = await bcrypt_executor.submit(
            bcrypt.hashpw,
            tornado.escape.utf8(self.get_argument('password')),
            bcrypt.gensalt()
        )
        return user.password_hash == hashed_password


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
