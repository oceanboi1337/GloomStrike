import flask, hashlib, tempfile, os, __main__, sys
from gloomstrike import network
from .. import app

router = flask.Blueprint('hashcrack', __name__)

def return_err(err: str):
    return flask.render_template(f'{router.name}.html', error=err)

@router.route('/', methods=['POST'])
def post():

    _hash = flask.request.form.get('hash')
    algorithm = flask.request.form.get('aglorithm')
    wordlist = flask.request.files.get('wordlist')
    local_wordlist = flask.request.form.get('local_wordlist')

    if not algorithm in hashlib.algorithms_available:
        return return_err('Invalid hashing algorithm')
    
    main_path = os.path.dirname(__main__.__file__)
    wordlist_dir = os.path.join(main_path, 'wordlists', 'hashcrack')

    if wordlist:
        
        if not os.path.exists(wordlist_dir):
            os.makedirs(wordlist_dir)

        save_path = os.path.join(wordlist_dir, wordlist.filename)

        if os.path.exists(save_path):
            return return_err('Wordlist already exists locally')
        
        try:
            wordlist.save(save_path)
        except Exception as e:
            return return_err('Failed to save wordlist locally')

    elif local_wordlist:

        if not local_wordlist.isdigit():
            return return_err('Invalid wordlist index')
        
        local_wordlist = int(local_wordlist)
        wordlists = os.listdir(wordlist_dir)

        if not local_wordlist < len(wordlists):
            return return_err('Invalid wordlist index')
        
        

    return flask.redirect('/hashcrack')

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