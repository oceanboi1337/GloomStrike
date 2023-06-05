import flask, hashlib, tempfile, os, __main__, sys
from gloomstrike import network, logger, checker
from .. import app

router = flask.Blueprint('checker', __name__)

@router.route('/', methods=['POST'])
def post():

    url = flask.request.form.get('url')
    threads = flask.request.form.get('threads', type=int)
    parameters = flask.request.form.get('parameters')
    csrf_url = flask.request.form.get('csrf-url')
    csrf = flask.request.form.get('csrf')
    
    usernames = flask.request.files.get('usernames')
    passwords = flask.request.files.get('passwords')
    combolist = flask.request.files.get('combolist')

    if ((csrf and not csrf_url) or (csrf_url and not csrf)) or (not (url and threads and parameters)) or (not ((usernames and passwords) or combolist)):
        return flask.redirect('/checker')
    
    usernames_list = []
    passwords_list = []
    combolist_list = []

    if usernames and passwords:

        while username := usernames.stream.readline():

            username = username.rstrip().decode()
            usernames_list.append(username)

        while password := passwords.stream.readline():

            password = password.rstrip().decode()
            passwords_list.append(password)

    if combolist:

        while combo := combolist.stream.readline():

            combo = combo.rstrip().decode()
            combolist_list.append(combo)
    
    _checker = checker.HttpChecker(url, parameters, csrf, csrf_url)

    object_hash = hash(_checker)

    if not _checker.load_list(usernames_list, passwords_list, combolist_list):
        return flask.redirect('/checker')

    if not _checker.start(threads=threads, background=True):
        return flask.redirect('/checker')
    
    app.running_tasks[object_hash] = {'type': 'HTTP Checker', 'object': _checker}
    
    return flask.redirect(f'/scans/{object_hash}')

@router.route('/', methods=['GET'])
def get():

    return flask.render_template('checker.html')