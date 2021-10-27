from api.tool import sort_by_name, decrypt_password
from cryptography.fernet import Fernet
from database.connector import open_session, close_session
from database.tables import User, Agent
from flask_login import current_user, login_required
from requests.exceptions import ConnectTimeout, ConnectionError
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import flask, json, logging, os, requests, subprocess


b_user = flask.Blueprint("user", __name__, template_folder="templates/")
POST_TIMEOUT = 30


def post_data(db, user_email, agent_type, agent_token):
    json_data = { "token": agent_token, "user": user_email }
    if agent_type == "g5k":
        user_db = db.query(User).filter(User.email == user_email).first()
        if user_db.g5k_user is None or len(user_db.g5k_user) == 0 or \
            user_db.g5k_pwd is None or len(user_db.g5k_pwd) == 0:
                raise ValueError('G5k credentials are missing')
        json_data["g5k_user"] = user_db.g5k_user
        json_data["g5k_password"] = user_db.g5k_pwd
    if agent_type == "iot-lab":
        user_db = db.query(User).filter(User.email == user_email).first()
        if user_db.iot_user is None or len(user_db.iot_user) == 0 or \
            user_db.iot_pwd is None or len(user_db.iot_pwd) == 0:
                raise ValueError('Iot-Lab credentials are missing')
        json_data["iot_user"] = user_db.iot_user
        json_data["iot_password"] = user_db.iot_pwd
    return json_data


def node_list_helper():
    result = { "errors": [], "nodes": {}, "duplicated": [] }
    db = open_session()
    for agent in db.query(Agent).filter(Agent.state == "connected").all():
        try:
            r_data = post_data(db, current_user.email, agent.type, agent.token)
            r = requests.post(url = "http://%s:%s/v1/user/node/list" % (agent.ip, agent.port),
                timeout = POST_TIMEOUT, json = r_data)
            if r.status_code == 200:
                r_json = r.json()
                duplicated_names = []
                for node in r_json:
                    if node in result["nodes"]:
                        duplicated_names.append(node)
                    else:
                        node_info = r_json[node]
                        node_info["type"] = agent.type
                        node_info["agent"] = agent.name
                        result["nodes"][node] = node_info
                if len(duplicated_names) > 0:
                    result["duplicated"] += duplicated_names
                    error_msg = "on agent '%s', duplicated names: %s" % (agent.name, duplicated_names)
                    result["errors"].append(error_msg)
                    logging.error(error_msg)
            else:
                error_msg = "on agent '%s', connection error with return code %d" % (agent.name, r.status_code)
                result["errors"].append(error_msg)
                logging.error(error_msg)
        except (ConnectionError, ConnectTimeout):
            agent.state = "disconnected"
            error_msg = "agent '%s' does not respond" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
        except Exception as e:
            error_msg = "connection failure to the agent '%s'" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
    close_session(db)
    if len(result["errors"]) == 0:
        result["nodes"] = sort_by_name(result["nodes"])
    return result


# REST API to connect the web UI and the agents
@b_user.route("/node/list")
@login_required
def node_list():
    return json.dumps(node_list_helper())


@b_user.route("/node/schedule")
@login_required
def node_schedule():
    result = { "errors": [], "nodes": {} }
    db = open_session()
    for agent in db.query(Agent).filter(Agent.state == "connected").all():
        try:
            r_data = post_data(db, current_user.email, agent.type, agent.token)
            r = requests.post(url = "http://%s:%s/v1/user/node/schedule" % (agent.ip, agent.port),
                timeout = POST_TIMEOUT, json = r_data)
            if r.status_code == 200:
                r_json = r.json()
                result["nodes"].update(r_json["nodes"])
            else:
                logging.error("schedule error: wrong answer from the agent '%s'" % agent.name)
        except (ConnectionError, ConnectTimeout):
            error_msg = "agent '%s' does not respond" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
        except:
            error_msg = "connection failure to the agent '%s'" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
    close_session(db)
    return json.dumps(result)


@b_user.route("/node/configuring")
@login_required
def node_configuring():
    result = { "errors": [], "raspberry": {}, "iot-lab": {}, "g5k": {} }
    db = open_session()
    for agent in db.query(Agent).filter(Agent.state == "connected").all():
        try:
            r_data = post_data(db, current_user.email, agent.type, agent.token)
            r = requests.post(url = "http://%s:%s/v1/user/configure" % (agent.ip, agent.port),
                timeout = POST_TIMEOUT, json = r_data)
            if r.status_code == 200 and agent.type in result:
                # Add the agent name to the node information
                json_data = r.json()
                for node in json_data:
                    json_data[node]["agent"] = agent.name
                result[agent.type].update(json_data)
            else:
                logging.error("configuring error: wrong answer from the agent '%s'" % agent.name)
        except (ConnectionError, ConnectTimeout):
            agent.state = "disconnected"
            error_msg = "agent '%s' does not respond" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
        except:
            error_msg = "connection failure to the agent '%s'" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
    close_session(db)
    for node_type in result:
        if node_type != "errors":
            result[node_type] = sort_by_name(result[node_type])
    return json.dumps(result)


@b_user.route("/node/deploying")
@login_required
def node_deploying():
    result = {
        "errors": [],
        "nodes": {},
        "states": { "raspberry": [], "iot-lab": [], "g5k": [] }
    }
    db = open_session()
    for agent in db.query(Agent).filter(Agent.state == "connected").all():
        try:
            r_data = post_data(db, current_user.email, agent.type, agent.token)
            r = requests.post(url = "http://%s:%s/v1/user/node/mine" % (agent.ip, agent.port),
                timeout = POST_TIMEOUT, json = r_data)
            if r.status_code == 200:
                json_data = r.json()
                result["states"][agent.type] = json_data["states"]
                for node in json_data["nodes"]:
                    # Sort the nodes by bin
                    bin_name = json_data["nodes"][node].pop("bin")
                    # Add the agent name to the node information
                    json_data["nodes"][node]["agent"] = agent.name
                    # No bin for nodes in 'configuring' state
                    if len(bin_name) > 0:
                        # Sort nodes by bin name
                        if bin_name not in result["nodes"]:
                            result["nodes"][bin_name] = { "raspberry": [], "iot-lab": [], "g5k": [] }
                        result["nodes"][bin_name][agent.type].append(json_data["nodes"][node])
            else:
                error_msg = "deploying error: wrong answer from the agent '%s' (return code %d)" % (
                    agent.name, r.status_code)
                logging.error(error_msg)
                result["errors"].append(error_msg)
        except (ConnectionError, ConnectTimeout):
            agent.state = "disconnected"
            error_msg = "agent '%s' does not respond" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
        except:
            error_msg = "connection failure to the agent '%s'" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
    close_session(db)
    return json.dumps(result)


@b_user.route("/node/updating")
@login_required
def node_updating():
    result = { "errors": [] }
    db = open_session()
    for agent in db.query(Agent).filter(Agent.state == "connected").all():
        try:
            r_data = post_data(db, current_user.email, agent.type, agent.token)
            r = requests.post(url = "http://%s:%s/v1/user/node/state" % (agent.ip, agent.port),
                timeout = POST_TIMEOUT, json = r_data)
            if r.status_code == 200:
                json_data = r.json()
                for node in json_data["nodes"]:
                    bin_name = json_data["nodes"][node].pop("bin")
                    # No bin for nodes in 'configuring' state
                    if len(bin_name) > 0:
                        # Sort nodes by bin name
                        if bin_name not in result:
                            result[bin_name] = { "raspberry": [], "iot-lab": [], "g5k": [] }
                        result[bin_name][agent.type].append(json_data["nodes"][node])
        except:
            error_msg = "connection failure to the agent '%s'" %  agent.name
            result["errors"].append(error_msg)
            logging.exception(error_msg)
    close_session(db)
    return json.dumps(result)


@b_user.route("/iot/data/<agent_name>/<job_id>")
@login_required
def iot_data(agent_name, job_id):
    db = open_session()
    agent = db.query(Agent).filter(Agent.name == agent_name).first()
    if agent is None:
        close_session()
        return flask.redirect("/user/manage?msg=no agent available")
    user = db.query(User).filter(User.email == current_user.email).first()
    iot_user = user.iot_user
    iot_pwd = user.iot_pwd
    close_session(db)
    # Check if the job_id is in my current jobs
    cmd = "iotlab-experiment -u %s -p %s get -l" % (iot_user, decrypt_password(iot_pwd))
    process = subprocess.run(cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
    json_data = json.loads(process.stdout)["items"]
    not_found = True
    for job in json_data:
        if str(job["id"]) == job_id:
            not_found = False
            break
    if not_found:
        logging.error("No job '%s' for the user '%s'" % (job_id, iot_user))
        return flask.redirect("/user/manage?msg=job not found")
    data_path = "iot_data/%s/%s.tar.gz" % (current_user.email, job_id)
    dir_path = "iot_data/%s" % current_user.email
    if not os.path.isdir(dir_path):
        os.mkdir(dir_path)
    if not os.path.isfile(data_path):
        # Download the file
        cmd = "iotlab-experiment -u %s -p %s get -i %s -a" % (
            iot_user, decrypt_password(iot_pwd), job_id)
        process = subprocess.run(cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        os.rename("%s.tar.gz" % job_id, data_path)
    return flask.send_file(data_path, as_attachment = True)


@b_user.route("/make/reserve", methods=["POST"])
@login_required
def make_reserve():
    result = { "total_nodes": 0, "wanted": 0, "errors": [] }
    nb_wanted = 0
    msg = ""
    db = open_session()
    for f in flask.request.json["filters"]:
        result["wanted"] += f["nb_nodes"]
        if "agent" in f:
            agent = db.query(Agent).filter(Agent.name == f["agent"]).filter(Agent.state == "connected").first()
            if agent is not None:
                # Make the reservation
                r_data = post_data(db, current_user.email, agent.type, agent.token)
                r_data["filter"] = f
                r_data["start_date"] = flask.request.json["start_date"]
                r_data["duration"] = flask.request.json["duration"]
                r = requests.post(url = "http://%s:%s/v1/user/reserve" % (agent.ip, agent.port),
                    timeout = POST_TIMEOUT, json = r_data)
                if r.status_code == 200:
                    r_json = r.json()
                    if "nodes" in r_json:
                        result["total_nodes"] += len(r.json()["nodes"])
                    if "error" in r_json:
                        result["errors"].append(r_json["error"])
                else:
                    logging.error("can not reserve nodes: wrong return code %d from '%s'" % (r.status_code, agent.name))
            else:
                logging.error("can not find the agent '%s' (maybe it is disconnected)" % f["agent"])
        elif "type" in f:
            agent_type = f["type"]
            del f["type"]
            for agent in db.query(Agent).filter(Agent.type == agent_type).filter(Agent.state == "connected").all():
                if f["nb_nodes"] > 0:
                    # Make the reservation
                    r_data = post_data(db, current_user.email, agent.type, agent.token)
                    r_data["filter"] = f
                    r_data["start_date"] = flask.request.json["start_date"]
                    r_data["duration"] = flask.request.json["duration"]
                    r = requests.post(url = "http://%s:%s/v1/user/reserve" % (agent.ip, agent.port),
                        timeout = POST_TIMEOUT, json = r_data)
                    if r.status_code == 200:
                        nb_nodes = len(r.json()["nodes"])
                        result["total_nodes"] += nb_nodes
                        f["nb_nodes"] -= nb_nodes
                    else:
                        logging.error("can not reserve nodes: wrong return code %d from '%s'" % (r.status_code, agent.name))
        else:
            logging.error("node reservation failure: no 'type' property and no 'agent' property in the POST data")
    close_session(db)
    return json.dumps(result)


@b_user.route("/make/deploy", methods=["POST"])
@login_required
def make_deploy():
    form_data = flask.request.form
    dep_name = None
    duration = None
    result = {}
    json_result = { "errors": []}
    for prop in form_data:
        if prop == "bin":
            bin_name = form_data[prop]
        else:
            node_name, _, prop_name = prop.rpartition("-")
            if prop_name == "agent":
                last_agent = form_data[prop]
                if last_agent not in result:
                    result[last_agent] = {}
                result[last_agent][node_name] = { "node_bin": bin_name }
            else:
                result[last_agent][node_name][prop_name] = form_data[prop]
    if len(result) == 0:
        return flask.redirect("/user/configure?msg=%s" % "No data available to deploy nodes")
    db = open_session()
    for agent_name in result:
        # Send the user SSH key to the agent
        user_db = db.query(User).filter(User.email == current_user.email).first()
        if user_db.ssh_key is not None and len(user_db.ssh_key) > 256:
            for node in result[agent_name]:
                result[agent_name][node]["account_ssh_key"] = user_db.ssh_key
        agent = db.query(Agent).filter(Agent.name == agent_name).first()
        r_data = post_data(db, current_user.email, agent.type, agent.token)
        r_data["nodes"] = result[agent_name]
        r = requests.post(url = "http://%s:%s/v1/user/deploy" % (agent.ip, agent.port),
            timeout = POST_TIMEOUT, json = r_data)
        if r.status_code == 200:
            r_json = r.json()
            if "error" in r_json and len(r_json["error"]) > 0:
                json_result["errors"].append(r_json["error"][0])
            else:
                json_result.update(r.json())
        else:
            json_result["errors"].append("wrong answer from the agent '%s'" % agent_name)
    close_session(db)
    if len(json_result["errors"]) > 0:
        return flask.redirect("/user/configure?msg=%s" % ",".join(json_result["errors"]))
    else:
        return flask.redirect("/user/manage")
    return json.dumps(json_result)


@b_user.route("/make/exec", methods=["POST"])
@login_required
def make_exec():
    result = { "errors": [] }
    json_data = flask.request.json
    # Use the function 'init_action_process' of agent_exec
    if "nodes" in json_data and "reconfiguration" in json_data:
        db = open_session()
        for agent_name in json_data["nodes"]:
            agent = db.query(Agent).filter(Agent.name == agent_name).first()
            r_data = post_data(db, current_user.email, agent.type, agent.token)
            r_data["nodes"] = json_data["nodes"][agent_name]
            r = requests.post(url = "http://%s:%s/v1/user/%s" % (agent.ip, agent.port, json_data["reconfiguration"]),
                timeout = POST_TIMEOUT, json = r_data)
            if r.status_code == 200:
                json_answer = r.json()
                if "error" in json_answer:
                    result["errors"].append(json_answer["error"])
                else:
                    failure = []
                    for node in json_answer:
                        if json_answer[node] != "success":
                            failure.append(node)
                    if len(failure) > 0:
                        result["errors"].append("nodes with failure: %s" % failure)
                    else:
                        result.update(json_answer)
            else:
                logging.error("reconfiguration failure: the agent '%s' fails to execute '%s'" % (
                    agent_name, json_data["reconfiguration"]))
                result["errors"].append("wrong answer from the agent '%s'" % agent_name)
        close_session(db)
    else:
        logging.error(
            "Missing parameters in POST data: 'nodes' and 'configuration' are required")
    return json.dumps(result)


@b_user.route("/settings/password", methods=["POST"])
@login_required
def user_pwd():
    msg = ""
    form_data = flask.request.form
    db = open_session()
    user = db.query(User).filter(User.email == current_user.email).first()
    if "password" in form_data and "confirm_password" in form_data:
        if form_data["password"] == form_data["confirm_password"]:
            user.password = generate_password_hash(form_data["password"], method="sha256")
            msg = "Credentials updated!"
        else:
            msg = "The two passwords are different. Credentials unchanged!"
    else:
        msg = "Missing data in the request. Credentials unchanged!"
    close_session(db)
    return flask.redirect("/user/settings?msg=" + msg)


@b_user.route("/settings/g5kpassword", methods=["POST"])
@login_required
def user_g5kpwd():
    msg = "update credentials failure!"
    form_data = flask.request.form
    db = open_session()
    user = db.query(User).filter(User.email == current_user.email).first()
    if "password" in form_data and "confirm_password" in form_data:
        if form_data["password"] == form_data["confirm_password"]:
            with open("secret.key", "rb") as keyfile:
                key = keyfile.read()
                encoded_pwd = form_data["password"].encode()
                f = Fernet(key)
                user.g5k_pwd = f.encrypt(encoded_pwd).decode()
            if "user" in form_data and len(form_data["user"]) > 0:
                user.g5k_user = form_data["user"]
            msg = "Password updated!"
        else:
            msg = "The two passwords are different. Password unchanged!"
    else:
        msg = "Missing data in the request. Password unchanged!"
    close_session(db)
    return flask.redirect("/user/settings?msg=" + msg)


@b_user.route("/settings/g5kdelete")
@login_required
def user_g5kdel():
    msg = "credentials successful deleted!"
    db = open_session()
    user = db.query(User).filter(User.email == current_user.email).first()
    user.g5k_user = ""
    user.g5k_pwd = ""
    close_session(db)
    return flask.redirect("/user/settings?msg=" + msg)


@b_user.route("/settings/iotpassword", methods=["POST"])
@login_required
def user_iotpwd():
    msg = "update credentials failure"
    form_data = flask.request.form
    db = open_session()
    user = db.query(User).filter(User.email == current_user.email).first()
    if "password" in form_data and "confirm_password" in form_data:
        if form_data["password"] == form_data["confirm_password"]:
            with open("secret.key", "r") as keyfile:
                key = keyfile.read()
                encoded_pwd = form_data["password"].encode()
                f = Fernet(key)
                user.iot_pwd = f.encrypt(encoded_pwd).decode()
            if "user" in form_data and len(form_data["user"]) > 0:
                user.iot_user = form_data["user"]
            msg = "Password updated!"
        else:
            msg = "The two passwords are different. Password unchanged!"
    else:
        msg = "Missing data in the request. Password unchanged!"
    close_session(db)
    return flask.redirect("/user/settings?msg=" + msg)


@b_user.route("/settings/iotdelete")
@login_required
def user_iotdel():
    msg = "credentials successful deleted!"
    db = open_session()
    user = db.query(User).filter(User.email == current_user.email).first()
    user.iot_user = ""
    user.iot_pwd = ""
    close_session(db)
    return flask.redirect("/user/settings?msg=" + msg)


@b_user.route("/settings/ssh", methods=["POST"])
@login_required
def user_ssh():
    msg = ""
    form_data = flask.request.form
    db = open_session()
    user = db.query(User).filter(User.email == current_user.email).first()
    if "ssh_key" in form_data:
        user.ssh_key = form_data["ssh_key"]
        msg = "SSH key updated!"
    else:
        msg = "Missing data in the request. SSH key unchanged!"
    close_session(db)
    return flask.redirect("/user/settings?msg=" + msg)


# HTML Pages
@b_user.route("/reserve")
@login_required
def reserve():
    result = node_list_helper()
    return flask.render_template("reserve.html", admin = current_user.is_admin, active_btn = "user_reserve",
        nodes = result["nodes"], duplicated = result["duplicated"])


@b_user.route("/configure")
@login_required
def configure():
    return flask.render_template("configure.html", admin = current_user.is_admin, active_btn = "user_configure",
        nodes = json.loads(node_configuring()))


@b_user.route("/manage")
@login_required
def manage():
    json_data = json.loads(node_deploying())
    return flask.render_template("manage.html", admin = current_user.is_admin, active_btn = "user_manage",
        nodes = json_data["nodes"], states = json_data["states"], errors = json_data["errors"])


@b_user.route("/settings")
@login_required
def settings():
    result = {}
    db = open_session()
    user = db.query(User).filter(User.email == current_user.email).first()
    if user is not None:
        status = "User"
        if user.is_admin:
            status = "Admin"
        ssh_key = ""
        if user.ssh_key is not None:
            ssh_key = user.ssh_key
        if os.path.isfile("vpn_keys/%s.conf" % current_user.email.replace("@", "_")):
            result = { "email": user.email, "ssh_key": ssh_key, "status": status, "vpn_key": True }
        else:
            result = { "email": user.email, "ssh_key": ssh_key, "status": status, "vpn_key": False }
        # G5k credentials
        if user.g5k_user is not None and len(user.g5k_user) > 0:
            result["g5k_user"] = user.g5k_user
        else:
            result["g5k_user"] = "undefined"
        if user.g5k_pwd is not None and len(user.g5k_pwd) > 0:
            result["g5k_pwd"] = True
        else:
            result["g5k_pwd"] = False
        # Iot-Lab credentials
        if user.iot_user is not None and len(user.iot_user) > 0:
            result["iot_user"] = user.iot_user
        else:
            result["iot_user"] = "undefined"
        if user.iot_pwd is not None and len(user.iot_pwd) > 0:
            result["iot_pwd"] = True
        else:
            result["iot_pwd"] = False
    close_session(db)
    return flask.render_template("settings.html", admin = current_user.is_admin, active_btn = "user_settings",
        user = result)


@b_user.route("/vpn/download/<vpn_key>")
@login_required
def vpn_download(vpn_key):
    if current_user.is_admin or current_user.email.replace("@", "_") == vpn_key:
        return flask.send_file("vpn_keys/%s.conf" % vpn_key, as_attachment = True)


@b_user.route("/envfactory")
@login_required
def env_factory():
    result = node_list_helper()["nodes"]
    agent_sort = {}
    for r in result:
        if result[r]["agent"] not in agent_sort:
            agent_sort[result[r]["agent"]] = []
        agent_sort[result[r]["agent"]].append(r)
    return flask.render_template("env_factory.html", admin = current_user.is_admin, active_btn = "env_factory",
        nodes=agent_sort)


@b_user.route("/envregister", methods = ["POST"])
def env_register():
    form_data = flask.request.form
    if form_data["img_path"] is None:
        return flask.redirect("/user/envfactory?msg=Fields must not be empty")
    img_name = os.path.basename(form_data["img_path"])
    if img_name.endswith(".tar.gz"):
        db = open_session()
        agent = db.query(Agent).filter(Agent.name == form_data["agent_name"]).first()
        if agent is None:
            close_session()
            return flask.redirect("/user/envfactory?msg=agent '%s' does not exist" % form_data["agent_name"])

        r_data = post_data(db, current_user.email, agent.type, agent.token)
        r_data.update(form_data)
        r = requests.post(url = "http://%s:%s/v1/user/environment/register" % (agent.ip, agent.port),
            timeout = POST_TIMEOUT, json = r_data)
        close_session(db)
        if r.status_code == 200:
            if "error" in r.json():
                return flask.redirect("/user/envfactory?msg=%s" % r.json()["error"])
            else:
                return flask.redirect("/user/manage")
        else:
            logging.error("Wrong answer from the agent '%s'. Status code: %d" % (
                form_data["agent_name"], r.status_code))
            return flask.redirect("/user/envfactory?msg=wrong agent answer from '%s'" % form_data["agent_name"])
    else:
        return flask.redirect("/user/envfactory?msg=wrong filetype")


@b_user.route("/powermonitoring")
@login_required
def power_monitoring():
    return flask.render_template("power_monitoring.html", admin = current_user.is_admin, active_btn = "user_power")


def power_data_helper(switch_name=None, period_str=None):
    result = node_list_helper()["nodes"]
    node_data = {}
    # Retrieve the name of the nodes
    for r in result:
        my_agent = result[r]["agent"]
        my_switch = result[r]["switch"]
        my_port = str(result[r]["port_number"])
        if my_agent not in node_data:
            node_data[my_agent] = {}
        if my_switch not in node_data[my_agent]:
            node_data[my_agent][my_switch] = {}
        node_data[my_agent][my_switch][my_port] = { "node": r, "consumptions": [] }
    # Add the power consumption of every port
    db = open_session()
    for agent_name in node_data:
        agent = db.query(Agent).filter(Agent.name == agent_name).first()
        r_data = post_data(db, current_user.email, agent.type, agent.token)
        if isinstance(period_str, str) and len(period_str) > 0:
            r_data["period"] = period_str
        if isinstance(switch_name, str) and len(switch_name) > 0:
            r_data["switch"] = switch_name 
        r = requests.post(url = "http://%s:%s/v1/user/switch/consumption" % (agent.ip, agent.port),
            timeout = POST_TIMEOUT, json = r_data)
        if r.status_code == 200:
            r_json = r.json()
            for cons in r_json:
                my_switch = cons["switch"]
                my_port = cons["port"]
                if agent_name not in node_data:
                    node_data[agent_name] = {}
                if my_switch not in node_data[agent_name]:
                    node_data[agent_name][my_switch] = {}
                if my_port not in node_data[agent_name][my_switch]:
                    node_data[agent_name][my_switch][my_port] = { "consumptions": [] }
                node_data[agent_name][my_switch][my_port]["consumptions"].append({
                    "time": cons["time"],
                    "consumption": float(cons["consumption"])
                })
        else:
            logging.error("Can not retrieve power monitoring values from agent '%s' (status code: %d)" %
                    (agent_name, r.status_code))
    close_session(db)
    # Remove the switch ports without consumptions or with every consumption equal to 0
    for agent in list(node_data.keys()):
        agent_w_cons = False
        for switch in list(node_data[agent].keys()):
            switch_w_cons = False
            for port in list(node_data[agent][switch].keys()):
                port_w_cons = False
                for cons in node_data[agent][switch][port]["consumptions"]:
                    if cons["consumption"] > 0:
                        port_w_cons = True
                        switch_w_cons = True
                        agent_w_cons = True
                if not port_w_cons:
                    del node_data[agent][switch][port]
            if not switch_w_cons:
                del node_data[agent][switch]
        if not agent_w_cons:
            del node_data[agent]
    return node_data


@b_user.route("/powermonitoring/data")
@login_required
def user_power_data(switch_name=None, period_str=None):
        return json.dumps(power_data_helper(switch_name, period_str))


# Do the same thing than the power_data_helper() without authentication
def power_get_helper(agent_name, switch_name, period):
    result = {}
    # Check the period unit: s (seconds), m (minutes), h (hours), d (days)
    last_char = period[-1]
    if last_char not in [ "s", "m", "h", "d" ]:
        return {"error": "wrong unit for the period parameter"}
    # Get the agent information
    db = open_session()
    agent = db.query(Agent
            ).filter(Agent.state == "connected"
            ).filter(Agent.name == agent_name
            ).first()
    if agent is None:
        close_session(db)
        return json.dumps({ "error": "agent '%s' does not exist" % agent_name })
    r = requests.post(url = "http://%s:%s/v1/user/node/list" % (agent.ip, agent.port),
            timeout = POST_TIMEOUT, json = { "token": agent.token }) 
    if r.status_code == 200:
        # Retrieve the name of the nodes
        node_list = r.json()
        for n in node_list:
            my_switch = node_list[n]["switch"]
            my_port = str(node_list[n]["port_number"])
            if my_switch == switch_name:
                if my_switch not in result:
                    result[my_switch] = {}
                result[my_switch][my_port] = { "node": n, "consumptions": [] }
        # Retrieve the port consumptions of the switch
        r = requests.post(url = "http://%s:%s/v1/user/switch/consumption" % (agent.ip, agent.port),
            timeout = POST_TIMEOUT, json = {
                "token": agent.token,
                "switch": switch_name,
                "period": period
            })
        if r.status_code == 200:
            r_json = r.json()
            for cons in r_json:
                my_switch = cons["switch"]
                my_port = cons["port"]
                if my_switch not in result:
                    result[my_switch] = {}
                if my_port not in result[my_switch]:
                    result[my_switch][my_port] = { "consumptions": [] }
                result[my_switch][my_port]["consumptions"].append({
                    "time": cons["time"],
                    "consumption": float(cons["consumption"])
                })
            # Remove the switch ports without consumptions or with every consumption equal to 0
            for switch in list(result.keys()):
                switch_w_cons = False
                for port in list(result[switch].keys()):
                    port_w_cons = False
                    for cons in result[switch][port]["consumptions"]:
                        if cons["consumption"] > 0:
                            port_w_cons = True
                            switch_w_cons = True
                    if not port_w_cons:
                        del result[switch][port]
                if not switch_w_cons:
                    del result[switch]
    close_session(db)
    return result


@b_user.route("/powermonitoring/get/<agent>/<switch>/<period>")
def user_power_get(agent, switch, period):
    return json.dumps(power_get_helper(agent, switch, period), indent = 4)


@b_user.route("/powermonitoring/download", methods=["POST"])
@login_required
def user_power_download():
    form_data = flask.request.form
    data = power_data_helper(form_data["switch"], form_data["period"])
    data_path = "rasp_data/%s/power_data.json" % current_user.email
    dir_path = "rasp_data/%s" % current_user.email
    if not os.path.isdir(dir_path):
        os.mkdir(dir_path)
    with open(data_path, "w") as fd:
        json.dump(data, fd, indent = 4)
    return flask.send_file(data_path, as_attachment = True)


@b_user.route("/tempmonitoring")
@login_required
def temp_monitoring():
    return flask.render_template("temp_monitoring.html", admin = current_user.is_admin, active_btn = "user_temp")


def temp_data_helper(agent_name=None, period_str=None):
    # Add the temperature consumption
    node_data = {}
    db = open_session()
    if agent_name is None or len(agent_name) == 0:
        agent_list = db.query(Agent
            ).filter(Agent.type == "raspberry"
            ).filter(Agent.state == "connected"
            ).all()
    else:
        agent_list = db.query(Agent
            ).filter(Agent.type == "raspberry"
            ).filter(Agent.state == "connected"
            ).filter(Agent.name == agent_name
            ).all()
    for agent in agent_list:
        r_data = post_data(db, current_user.email, agent.type, agent.token)
        if isinstance(period_str, str) and len(period_str) > 0:
            r_data["period"] = period_str
        r = requests.post(url = "http://%s:%s/v1/user/node/temperature" % (agent.ip, agent.port),
            timeout = POST_TIMEOUT, json = r_data)
        if r.status_code == 200:
            r_json = r.json()
            for cons in r_json:
                if agent.name not in node_data:
                    node_data[agent.name] = {}
                node_name = cons["node"]
                if node_name not in node_data[agent.name]:
                    node_data[agent.name][node_name] = { "consumptions": [] }
                node_data[agent.name][node_name]["consumptions"].append({
                    "time": cons["time"],
                    "consumption": cons["consumption"]
                })
        else:
            logging.error("Can not retrieve temperature monitoring values from agent '%s' (status code: %d)" %
                    (agent.name, r.status_code))
    close_session(db)
    # Remove the switch ports without consumptions or with every consumption equal to 0
    for agent in list(node_data.keys()):
        agent_w_cons = False
        for node in list(node_data[agent].keys()):
            node_w_cons = False
            for cons in node_data[agent][node]["consumptions"]:
                if cons["consumption"] > 0:
                    node_w_cons = True
                    agent_w_cons = True
            if not node_w_cons:
                del node_data[agent][node]
        if not agent_w_cons:
            del node_data[agent]
    return node_data


@b_user.route("/tempmonitoring/data")
@login_required
def user_temp_data(period_str=None):
        return json.dumps(temp_data_helper(period_str=period_str))


# Do the same thing than the temp_data_helper() without authentication
def temp_get_helper(agent_name, period):
    result = {}
    # Check the period unit: s (seconds), m (minutes), h (hours), d (days)
    last_char = period[-1]
    if last_char not in [ "s", "m", "h", "d" ]:
        return {"error": "wrong unit for the period parameter"}
    # Get the agent information
    db = open_session()
    agent = db.query(Agent
            ).filter(Agent.state == "connected"
            ).filter(Agent.name == agent_name
            ).first()
    if agent is None:
        close_session(db)
        return json.dumps({ "error": "agent '%s' does not exist" % agent_name })
    r_data = post_data(db, current_user.email, agent.type, agent.token)
    if isinstance(period, str) and len(period) > 0:
        r_data["period"] = period
    r = requests.post(url = "http://%s:%s/v1/user/node/temperature" % (agent.ip, agent.port),
        timeout = POST_TIMEOUT, json = r_data)
    if r.status_code == 200:
        r_json = r.json()
        for cons in r_json:
            node_name = cons["node"]
            if node_name not in result:
                result[node_name] = { "consumptions": [] }
            result[node_name]["consumptions"].append({
                "time": cons["time"],
                "consumption": cons["consumption"]
            })
    else:
        logging.error("Can not retrieve temperature monitoring values from agent '%s' (status code: %d)" %
                (agent.name, r.status_code))
    close_session(db)
    # Remove the switch ports without consumptions or with every consumption equal to 0
    for node in list(result.keys()):
        node_w_cons = False
        for cons in result[node]["consumptions"]:
            if cons["consumption"] > 0:
                node_w_cons = True
        if not node_w_cons:
            del result[node]
    close_session(db)
    return result


@b_user.route("/tempmonitoring/get/<agent>/<period>")
def user_temp_get(agent, period):
    return json.dumps(temp_get_helper(agent, period), indent = 4)


@b_user.route("/tempmonitoring/download", methods=["POST"])
@login_required
def user_temp_download():
    form_data = flask.request.form
    data = temp_data_helper(form_data["agent"], form_data["period"])
    data_path = "rasp_data/%s/temp_data.json" % current_user.email
    dir_path = "rasp_data/%s" % current_user.email
    if not os.path.isdir(dir_path):
        os.mkdir(dir_path)
    with open(data_path, "w") as fd:
        json.dump(data, fd, indent = 4)
    return flask.send_file(data_path, as_attachment = True)
