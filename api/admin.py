from api.tool import sort_by_name
from database.connector import open_session, close_session, row2elem, row2dict
from database.tables import User, Worker
from flask_login import current_user, login_required
from lib.config_loader import load_config
import flask, functools, json, logging, requests


b_admin = flask.Blueprint("admin", __name__, template_folder="templates/")


def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flask.abort(403)
        return f(*args, **kwargs)
    return decorated_function


# User Management
@b_admin.route("/user")
@login_required
@admin_required
def list_user():
    pending_users = []
    authorized_users = []
    admin_users = []
    db = open_session()
    users = db.query(User).all()
    for u in users:
        user_dict = {
            "email": u.email,
            "confirmed_email": u.confirmed_email,
            "is_authorized": u.is_authorized,
            "is_admin": u.is_admin
        }
        if u.is_authorized:
            if u.is_admin:
                admin_users.append(user_dict)
            else:
                authorized_users.append(user_dict)
        else:
            pending_users.append(user_dict)
    close_session(db)
    return flask.render_template("user.html", admin = current_user.is_admin, active_btn = "admin_user",
        pending_users = pending_users, authorized_users = authorized_users, admin_users = admin_users,
        webui_str = "%s:%s" % (load_config()["ip"], load_config()["port_number"]))


@b_admin.route("/user/remove/<email>")
@login_required
@admin_required
def remove_user(email):
    if email is not None:
        db = open_session()
        user = db.query(User).filter(User.email == email).first()
        if user is not None:
            db.delete(user)
        close_session(db)
    return list_user()


@b_admin.route("/user/unauthorize/<email>")
@login_required
@admin_required
def unauthorize_user(email):
    if email is not None:
        db = open_session()
        user = db.query(User).filter(User.email == email).first()
        if user is not None:
            user.is_authorized = False
        close_session(db)
    return list_user()


@b_admin.route("/user/authorize/<email>")
@login_required
@admin_required
def authorize_user(email):
    if email is not None:
        db = open_session()
        user = db.query(User).filter(User.email == email).first()
        if user is not None:
            user.is_authorized = True
        close_session(db)
    return list_user()


@b_admin.route("/user/revoke/<email>")
@login_required
@admin_required
def revoke_user(email):
    if email is not None:
        db = open_session()
        user = db.query(User).filter(User.email == email).first()
        if user is not None:
            user.is_admin = False
        close_session(db)
    return list_user()


@b_admin.route("/user/promote/<email>")
@login_required
@admin_required
def promote_user(email):
    if email is not None:
        db = open_session()
        user = db.query(User).filter(User.email == email).first()
        if user is not None and user.is_authorized:
            user.is_admin = True
        close_session(db)
    return list_user()


# Worker management
@b_admin.route("/worker")
@b_admin.route("/worker/<error>")
@login_required
@admin_required
def list_worker(error=None):
    result = {"worker_key": {
        "properties": { "name": [], "ip": [], "port": [], "token": [] },
        "existing": []
    }}
    db = open_session()
    for w in db.query(Worker).all():
        result["worker_key"]["existing"].append({
            "name": w.name,
            "type": w.type,
            "ip": w.ip,
            "port": w.port,
            "token": w.token
        })
    close_session(db)
    # Display the type of the worker
    if error is None or len(error) == 0:
        return flask.render_template("admin.html", admin = current_user.is_admin, active_btn = "admin_worker",
            elem_type = "worker", elements = result,
            webui_str = "%s:%s" % (load_config()["ip"], load_config()["port_number"]))
    else:
        return flask.render_template("admin.html", admin = current_user.is_admin, active_btn = "admin_worker",
            elem_type = "worker", elements = result, msg = error,
            webui_str = "%s:%s" % (load_config()["ip"], load_config()["port_number"]))


@b_admin.route("/add/worker", methods=[ "POST" ])
@login_required
@admin_required
def add_worker():
    worker_ip = flask.request.form["ip"]
    worker_port = flask.request.form["port"]
    worker_token = flask.request.form["token"]
    worker_type = ""
    msg = ""
    try:
        # Test the connection to the worker
        r = requests.get(url = "http://%s:%s/v1/debug/status" % (worker_ip, worker_port))
        if r.status_code != 200 or "status" not in r.json():
            msg = "wrong answer from the worker '%s:%s'" % (worker_ip, worker_port)
        else:
            worker_type = r.json()["type"]
        # Test the authentication token
        r = requests.post(url = "http://%s:%s/v1/debug/auth" % (worker_ip, worker_port), json = { "token": worker_token })
        if r.status_code != 200 or "auth" not in r.json():
            msg = "wrong token for the worker '%s:%s'" % (worker_ip, worker_port)
        # Add the worker to my database
        if len(msg) == 0:
            db = open_session()
            new_worker = Worker()
            new_worker.name = flask.request.form["name"]
            new_worker.type = worker_type
            new_worker.ip = worker_ip
            new_worker.port = worker_port
            new_worker.token = worker_token
            db.add(new_worker)
            close_session(db)
    except:
        logging.exception("add worker failure")
        msg = "can not add the worker '%s:%s'" % (worker_ip, worker_port)
    return list_worker(msg)


@b_admin.route("/delete/worker/<worker_name>")
@login_required
@admin_required
def delete_worker(worker_name):
    if worker_name is not None:
        db = open_session()
        worker = db.query(Worker).filter(Worker.name == worker_name).first()
        if worker is not None:
            db.delete(worker)
        close_session(db)
    return list_worker()


# Other element management
@b_admin.route("/get/<el_type>")
@b_admin.route("/get/<el_type>/<error>")
@login_required
@admin_required
def get(el_type, error=None):
    result = { "errors": []}
    worker_types = load_config()["%s_provider" % el_type]
    if worker_types is None or len(worker_types) == 0:
        result["errors"].append("missing '%s_provider' property in the configuration file" % el_type)
        return flask.render_template("admin.html", admin = current_user.is_admin, active_btn = "admin_%s" % el_type,
            elem_type = el_type, elements = result, msg = result["errors"][0],
            webui_str = "%s:%s" % (load_config()["ip"], load_config()["port_number"]))
    db = open_session()
    workers = db.query(Worker).filter(Worker.type.in_(worker_types)).all()
    for w in workers:
        result[w.name] = { "properties": [], "existing": {} }
        # Get the element properties to register new elements
        r = requests.post(url = "http://%s:%s/v1/admin/add/%s" % (w.ip, w.port, el_type), json = { "token": w.token })
        if r.status_code != 200 or "missing" not in r.json():
            result["errors"].append("wrong answer from the worker '%s'" % w.name)
        else:
            result[w.name]["properties"] = r.json()["missing"]
            for prop in result[w.name]["properties"]:
                if "no_values" in result[w.name]["properties"][prop]:
                    result[w.name]["properties"] = "Missing '%s' elements to create '%s' elements." % (prop, el_type)
        # Get the existing elements
        r = requests.post(url = "http://%s:%s/v1/user/%s/list" % (w.ip, w.port, el_type), json = { "token": w.token })
        if r.status_code != 200:
            result["errors"].append("can not get the list of %ss from the worker '%s'" % (el_type, w.name))
        else:
            node_info = r.json()
            for el_name in node_info:
                one_node = node_info[el_name]
                one_node["name"] = el_name
                result[w.name]["existing"][el_name] = one_node
    close_session(db)
    for worker in result:
        if worker != "errors":
            result[worker]["existing"] = sort_by_name(result[worker]["existing"])
    if len(result["errors"]) == 0:
        return flask.render_template("admin.html", admin = current_user.is_admin, active_btn = "admin_%s" % el_type,
            elem_type = el_type, elements = result,
            webui_str = "%s:%s" % (load_config()["ip"], load_config()["port_number"]))
    else:
        return flask.render_template("admin.html", admin = current_user.is_admin, active_btn = "admin_%s" % el_type,
            elem_type = el_type, elements = result, msg = ",".join(result["errors"]),
            webui_str = "%s:%s" % (load_config()["ip"], load_config()["port_number"]))


@b_admin.route("/add/<el_type>/", methods=[ "POST" ])
@login_required
@admin_required
def add(el_type):
    db = open_session()
    try:
        worker_name = flask.request.form["worker"]
        # Get the worker information
        worker = db.query(Worker).filter(Worker.name == worker_name).first()
        forbidden_props = [ "worker" ]
        json_args = {}
        for prop in flask.request.form:
            if prop not in forbidden_props:
                json_args[prop] = flask.request.form[prop]
        json_args["token"] = worker.token
        # Register the element to the worker
        r = requests.post(url = "http://%s:%s/v1/admin/add/%s" % (worker.ip, worker.port, el_type), json = json_args)
        if r.status_code != 200:
            msg = "can not add the %s '%s' to the worker '%s'" % (el_type, flask.request.form["name"], worker.name)
        elif el_type not in r.json():
            if "check" in r.json():
                msg = r.json()["check"]
            else:
                msg = "wrong answer from '%s' for the %s '%s'"% (worker.name, el_type, flask.request.form["name"])
        else:
            msg = ""
    except:
        logging.exception("add worker failure")
        msg = "wrong %s configuration for '%s'" % (el_type, flask.request.form["name"])
    close_session(db)
    return get(el_type, msg)


@b_admin.route("/delete/<el_type>/<worker_name>/<el_name>")
@login_required
@admin_required
def delete(el_type, worker_name, el_name):
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token, "name": el_name }
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    msg = ""
    try:
        # Delete the element to the worker
        r = requests.post(url = "http://%s:%s/v1/admin/delete/%s" % (worker_ip, worker_port, el_type), json = json_args)
        if r.status_code != 200:
            msg = "can not delete the %s '%s' to the worker '%s:%s'" % (el_type, el_name, worker_ip, worker_port)
        elif "delete" not in r.json():
            msg = "wrong answer while deleting the %s '%s'" % (el_type, el_name)
    except:
        logging.exception("delete element failure")
        msg = "can not delete the %s '%s'" % (el_type, el_name)
    return get(el_type, msg)


# Switch operations
@b_admin.route("/switch/<worker_name>/<switch_name>")
@login_required
@admin_required
def poe_status(worker_name, switch_name):
    result = {}
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token }
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        # Get the PoE status of all switch ports
        r = requests.post(url = "http://%s:%s/v1/admin/switch/ports/%s" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
    except:
        logging.exception("get PoE status for the switch '%s' failed (worker: '%s')" % (switch_name, worker_name))
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/<switch_name>/nodes", methods = [ "POST" ])
@login_required
@admin_required
def switch_nodes(worker_name, switch_name):
    result = {}
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token }
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        # Get the PoE status of all switch ports
        r = requests.post(url = "http://%s:%s/v1/admin/switch/nodes/%s" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
    except:
        logging.exception("get PoE status for the switch '%s' failed (worker: '%s')" % (switch_name, worker_name))
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/<switch_name>/turn_off", methods = [ "POST" ])
@login_required
@admin_required
def turn_off(worker_name, switch_name):
    result = {}
    if "ports" not in flask.request.json:
        return json.dumps(result)
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token, "ports": flask.request.json["ports"] }
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        # Turn off switch ports
        r = requests.post(url = "http://%s:%s/v1/admin/switch/turn_off/%s" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
    except:
        logging.exception("turn off PoE port of the switch '%s' failed (worker: '%s')" % (switch_name, worker_name))
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/<switch_name>/turn_on", methods = [ "POST" ])
@login_required
@admin_required
def turn_on(worker_name, switch_name):
    result = {}
    if "ports" not in flask.request.json:
        return json.dumps(result)
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token, "ports": flask.request.json["ports"] }
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        # Turn on switch ports
        r = requests.post(url = "http://%s:%s/v1/admin/switch/turn_on/%s" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
    except:
        logging.exception("turn on PoE port of the switch '%s' failed (worker: '%s')" % (switch_name, worker_name))
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/<switch_name>/init_detect", methods = [ "POST" ])
@login_required
@admin_required
def init_detect(worker_name, switch_name):
    result = {}
    if "ports" not in flask.request.json:
        return json.dumps(result)
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token, "ports": flask.request.json["ports"] }
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        r = requests.post(url = "http://%s:%s/v1/admin/switch/init_detect/%s" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
    except:
        logging.exception("configure node failure: worker: '%s', switch: '%s',  ports: %s" % (worker_name, switch_name, ports))
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/<switch_name>/dhcp_conf", methods = [ "POST" ])
@login_required
@admin_required
def dhcp_conf(worker_name, switch_name):
    result = { "errors": [] }
    flask_data = flask.request.json
    if "port" not in flask_data or "macs" not in flask_data or \
            "ip_offset" not in flask_data and "network" not in flask_data:
        result["errors"].append("Required parameters: 'port', 'macs', 'network' and 'ip_offset'")
        return json.dumps(result)
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token }
    json_args.update(flask_data)
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        r = requests.post(url = "http://%s:%s/v1/admin/switch/dhcp_conf/%s" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
    except:
        logging.exception("configure node failure: worker: '%s', switch: '%s',  ports: %s" % (worker_name, switch_name, ports))
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/<switch_name>/dhcp_conf/del", methods = [ "POST" ])
@login_required
@admin_required
def dhcp_conf_del(worker_name, switch_name):
    result = { "errors": [] }
    flask_data = flask.request.json
    if "ip" not in flask_data or "mac" not in flask_data:
        result["errors"].append("Required parameters: 'ip' and 'mac'")
        return json.dumps(result)
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token }
    json_args.update(flask_data)
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        r = requests.post(url = "http://%s:%s/v1/admin/switch/dhcp_conf/%s/del" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
    except:
        logging.exception("configure node failure: worker: '%s', switch: '%s',  ports: %s" % (worker_name, switch_name, ports))
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/<switch_name>/node_conf", methods = [ "POST" ])
@login_required
@admin_required
def node_conf(worker_name, switch_name):
    result = { "errors": [] }
    flask_data = flask.request.json
    if "node_ip" not in flask_data or "port" not in flask_data:
        result["errors"].append("Required parameters: 'node_ip', 'port'")
        return json.dumps(result)
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token }
    json_args.update(flask_data)
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        r = requests.post(url = "http://%s:%s/v1/admin/switch/node_conf/%s" % (worker_ip, worker_port, switch_name), json = json_args)
        if r.status_code == 200:
            result = r.json()
        else:
            result["errors"].append("wrong answer from the worker '%s'" % worker_name)
    except:
        logging.exception("configure node failure: worker: '%s', switch: '%s',  ports: %s" % (worker_name, switch_name, ports))
        result["errors"].append("node configuration from the worker '%s' failed" % worker_name)
    return json.dumps(result)


@b_admin.route("/switch/<worker_name>/clean_detect", methods = [ "POST" ])
@login_required
@admin_required
def clean_detect(worker_name):
    result = { "errors": [] }
    # Get the worker information
    db = open_session()
    worker = db.query(Worker).filter(Worker.name == worker_name).first()
    json_args = { "token": worker.token }
    worker_ip = worker.ip
    worker_port = worker.port
    close_session(db)
    try:
        r = requests.post(url = "http://%s:%s/v1/admin/switch/clean_detect" % (worker_ip, worker_port), json = json_args)
        if r.status_code == 200:
            result = r.json()
        else:
            result["errors"].append("wrong answer from the worker '%s'" % worker_name)
    except:
        logging.exception("clean detect failure: worker: '%s'" % worker_name)
        result["errors"].append("can not clean the TFTP folder of the worker '%s'" % worker_name)
    return json.dumps(result)

