import flask
from gloomstrike import network, hashcrack
from .. import app

router = flask.Blueprint('scans', __name__)

@router.route('/', methods=['POST'])
def post():

    pass

@router.route('/', methods=['GET'])
def get():

    return flask.render_template('scans.html', objects=app.running_tasks)

@router.route('/<int:id>', methods=['GET'])
def get_int(id):

    action = flask.request.args.get('action')

    if (object := app.running_tasks.get(id)) == None:
        return flask.make_response('<h1>Scan not found</h1>', 404)

    if action == 'delete':

        del app.running_tasks[id]
        return flask.redirect('/scans')

    elif action == 'stop':

        object.stop()
        return flask.redirect('/scans')
    
    _type = object['type']
    _object = object['object']

    match type(_object):

        case network.PortScanner:
            return flask.render_template('portscan.html', hash=id, object=_object, type=_type, progress=_object.progress)
        case network.HostScanner:
            return flask.render_template('hostscan.html', hash=id, object=_object, type=_type, progress=_object.progress)
        case hashcrack.Hashcrack:
            print(_object._hashes)
            return flask.render_template('cracking.html', hash=id, object=_object, type=_type, progress=0)