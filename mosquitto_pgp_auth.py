import gnupg
import json
from datetime import datetime
import mosquitto_auth

gpg = None
valid_broker_hosts = {}

def plugin_init(opts):
    global gpg, valid_broker_hosts
    conf = dict(opts)
    gpg = gnupg.GPG(gnupghome=conf.get('pgp_dir'))
    broker_hosts = str(conf.get('broker_hosts'))
    valid_broker_hosts = broker_hosts.split(',')

def unpwd_check(username, password):
    stripped_message = password[password.index('{'):password.rindex('}')+1]
    try:
        auth_message = json.loads(stripped_message)
    except:
        return False
    if not auth_message:
        return False
    import_res = gpg.import_keys(auth_message['key'])
    if not import_res.count == 1:
         return False
    check = gpg.verify(password)
    if not check:
        return False
    if not username == check.key_id:
        return False
    # Check time and broker are correct
    if not auth_message['broker'] in valid_broker_hosts:
        return False
    utc_datetime = int(datetime.utcnow().strftime("%s"))/60 # unixtime in minutes
    supplied_datetime = int(auth_message['time'])
    time_delta = supplied_datetime - utc_datetime
    if (time_delta > 3) or (time_delta < -3): # 6 minute window to allow for plenty of clock skew
        return False
    # If they made it this far they are authenticated
    return True

def acl_check(clientid, username, topic, access):
    if access == mosquitto_auth.MOSQ_ACL_READ:
        if mosquitto_auth.topic_matches_sub('user/' + username + '/inbox', topic): # user reading their own inbox
            return True
        elif mosquitto_auth.topic_matches_sub('user/+/profile', topic): # user reading another users profile
            return True
        elif mosquitto_auth.topic_matches_sub('user/+/items', topic): # user reading another users items
            return True
    elif access == mosquitto_auth.MOSQ_ACL_WRITE:
        if mosquitto_auth.topic_matches_sub('user/+/inbox', topic): # user sending a message
            return True
        elif mosquitto_auth.topic_matches_sub('user/' + username + '/items', topic): # user updating their own items
            return True
        elif mosquitto_auth.topic_matches_sub('user/' + username + '/profile', topic): # user updating their own profile
            return True
    return False
