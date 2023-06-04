import flask, tempfile, io
from gloomstrike import fuzzer, logger
from .. import app
router = flask.Blueprint('fuzzer', __name__)

@router.route('/', methods=['POST'])
def post():

    target = flask.request.form.get('target')
    threads = flask.request.form.get('threads', type=int)
    depth = flask.request.form.get('depth', type=int)
    dir_wordlist = flask.request.files.get('dir_wordlist')
    file_wordlist = flask.request.files.get('file_wordlist')
    sub_wordlist = flask.request.files.get('sub_wordlist')

    if not (target and dir_wordlist and file_wordlist):
        return flask.redirect('/fuzzer')

    if dir_wordlist and not sub_wordlist:

        files = []
        dirs = []

        while dir := dir_wordlist.stream.readline():
            dir = dir.rstrip().decode()
            dirs.append(dir)

        while file := file_wordlist.stream.readline():
            file = file.rstrip().decode()
            files.append(file)

        url_fuzzer = fuzzer.UrlFuzzer(dirs, files)

        if not url_fuzzer.start(target=target, max_depth=depth, threads=threads, background=True):

            logger.log('Failed to start fuzzing')
            return flask.redirect('/fuzzer')

        object_hash = hash(url_fuzzer)

        app.running_tasks[object_hash] = {'type': 'URL Fuzzer', 'object': url_fuzzer}

        return flask.redirect(f'/scans/{object_hash}')

@router.route('/', methods=['GET'])
def get():

    return flask.render_template('fuzzer.html')