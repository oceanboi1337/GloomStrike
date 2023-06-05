import flask
from gloomstrike import network, hashcrack, fuzzer, checker
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
    
    _object = object['object']
    _type = object['type']
    
    match type(_object):

        case network.PortScanner:
            return flask.render_template('results/portscan.html', hash=id, object=_object)
        case network.HostScanner:
            return flask.render_template('results/hostscan.html', hash=id, object=_object)
        case hashcrack.Hashcrack:
            return flask.render_template('results/cracking.html', hash=id, object=_object)
        case fuzzer.UrlFuzzer:
            return flask.render_template('results/fuzzing.html', hash=id, object=_object, type=_type)
        case fuzzer.SubFuzzer:
            return flask.render_template('results/fuzzing.html', hash=id, object=_object, type=_type)
        case checker.HttpChecker:
            return flask.render_template('results/checker.html', hash=id, object=_object, type=_type)