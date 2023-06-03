import flask, hashlib, tempfile, os, __main__, sys
from gloomstrike import network, logger, hashcrack
from .. import app

router = flask.Blueprint('hashcrack', __name__)

@router.route('/', methods=['POST'])
def post():

    _hash = flask.request.form.get('hash')
    algorithm = flask.request.form.get('algorithm')
    wordlist = flask.request.files.get('wordlist')
    local_wordlist = flask.request.form.get('local_wordlist')

    if not algorithm in hashlib.algorithms_available:
        return flask.redirect('/hashcrack')
    
    main_path = os.path.dirname(__main__.__file__)
    wordlist_dir = os.path.join(main_path, 'wordlists', 'hashcrack')

    if wordlist:
        
        if not os.path.exists(wordlist_dir):
            os.makedirs(wordlist_dir)

        save_path = os.path.join(wordlist_dir, wordlist.filename)

        if not os.path.exists(save_path):
            
            try:

                wordlist.save(save_path)

            except Exception as e:

                logger.log(f'Failed to save wordlist: {e}')
                return flask.redirect('/hashcrack')
        
        wordlist = save_path

    elif local_wordlist:

        if not local_wordlist.isdigit():
            return flask.redirect('/hashcrack')
        
        local_wordlist = int(local_wordlist)
        wordlists = os.listdir(wordlist_dir)

        if not local_wordlist < len(wordlists):
            return flask.redirect('/hashcrack')
        
        wordlist = os.path.join(wordlist_dir, wordlists[local_wordlist])

    if not wordlist:
        return flask.redirect('/hashcrack')
    
    hash_cracker = hashcrack.Hashcrack(potfile=os.path.join(main_path, 'potfile.txt'))

    if not hash_cracker.load_hashes([_hash]) or not hash_cracker.load_wordlist(wordlist):
        return flask.redirect('/hashcrack')

    if not hash_cracker.start(algorithm=algorithm, background=True):
        return flask.redirect('/hashcrack')

    object_hash = hash(hash_cracker)

    app.running_tasks[object_hash] = {'type': 'Hash Cracker', 'object': hash_cracker}

    return flask.redirect(f'/scans/{object_hash}')

@router.route('/', methods=['GET'])
def get():
    
    algos = hashlib.algorithms_available

    wordlists = []

    main_path = os.path.dirname(__main__.__file__)
    wordlist_dir = os.path.join(main_path, 'wordlists', 'hashcrack')
    
    if not os.path.exists(wordlist_dir):
        os.makedirs(wordlist_dir)

    wordlists = os.listdir(wordlist_dir)
    
    return flask.render_template('hashcrack.html',
                                 algos=algos,
                                 wordlists=wordlists)