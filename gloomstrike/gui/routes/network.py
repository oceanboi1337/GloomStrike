import flask

router = flask.Blueprint('network', __name__)

@router.route('/')
def network():

    return flask.render_template('network.html')
