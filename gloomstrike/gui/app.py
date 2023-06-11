import flask, threading, os, sys
from gloomstrike import logger

running_tasks = {}

class WebServer:

    def __init__(self, host: str = '0.0.0.0', port: int = 1337):

        self._host = host
        self._port = port

        self._app = flask.Flask('GloomStrike',
                                template_folder='gloomstrike/gui/templates',
                                static_folder='gloomstrike/gui/static')
        
        self._app.config['TEMPLATES_AUTO_RELOAD'] = True
        self._app.config['MAX_CONTENT_LENGTH'] = (1024 ** 3) * 10 # 10 GB
        self._app_thread = None

    def add_router(self, prefix: str, name: str, router: flask.Blueprint):

        self._app.register_blueprint(router, url_prefix=prefix, name=name)

    def start(self):

        try:

            self._app_thread = threading.Thread(target=self._app.run, args=[self._host, self._port])
            self._app_thread.daemon = True
            self._app_thread.start()

            return True
        
        except Exception as e:
            logger.log(f'Failed to start flask server: {e}', level=logger.Level.ERROR)
        
        return False
