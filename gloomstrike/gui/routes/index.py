import flask

router = flask.Blueprint('index', __name__)

@router.route('/')
def index():

    return flask.render_template('index.html')
