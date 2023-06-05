import flask, hashlib, tempfile, os, __main__, sys
from gloomstrike import network, logger, hashcrack
from .. import app

router = flask.Blueprint('checker', __name__)

@router.route('/', methods=['POST'])
def post():

    pass

@router.route('/', methods=['GET'])
def get():

    return flask.render_template('checker.html')