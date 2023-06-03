import flask
from gloomstrike import network
from .. import app

router = flask.Blueprint('network', __name__)

@router.route('/', methods=['POST'])
def post():

    target = flask.request.form.get('target')
    ports = flask.request.form.get('ports')
    protocol = flask.request.form.get('protocol')

    if flask.request.form.get('ps'):

        port_scanner = network.PortScanner(target=target, ports=ports)
        id = hash(port_scanner)

        if not port_scanner.ready or not port_scanner.scan(background=True):
            return flask.render_template('network.html', {'error': 'Failed to start scan'})
        
        app.running_tasks[id] = {'type': 'Port Scan', 'object': port_scanner}

        return flask.redirect(f'/scans/{id}')
    
    elif flask.request.form.get('d'):

        host_scanner = network.HostScanner(target)
        id = hash(host_scanner)

        protocol = network.Protocol.ARP

        if flask.request.form.get('protocol') == 'icmp':
            protocol = network.Protocol.ICMP

        if not host_scanner.ready or not host_scanner.start(protocol=protocol, background=True):
            return flask.render_template('network.html', {'error': 'Failed to start scan'})
        
        app.running_tasks[id] = {'type': 'Host Scan', 'object': host_scanner}

        return flask.redirect(f'/scans/{id}')

    return flask.render_template('network.html')

@router.route('/', methods=['GET'])
def get():

    print(app.running_tasks)

    return flask.render_template('network.html')
