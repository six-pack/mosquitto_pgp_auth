import gnupg
import json
from calendar import timegm
from time import gmtime
import mosquitto_auth
gpg = None
valid_broker_hosts = {}

def plugin_init(opts):
    global gpg, valid_broker_hosts
    conf = dict(opts)
    gpg = gnupg.GPG(gnupghome=conf.get('pgp_dir'))
    broker_hosts = str(conf.get('broker_hosts'))
    valid_broker_hosts = broker_hosts.split(',')
    broker_key = conf.get('broker_key')

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
        # Maybe we don't have their public key stored, import it and try again
        import_res = gpg.import_keys(auth_message['key'])
        if not import_res.count == 1:
            #TODO watch out for public key flooding - limit user supplied input to 1 key before and delete here if they
            # submit more than 1
            return False
        else:
            check = gpg.verify(password)
            if not check: # we imported a key but the auth didn't check out - purge the imported key
                gpg.delete_keys(import_res.fingerprints[0]) # TODO: check for multiple keys
                return False
        return False
    if not username == check.key_id:
        return False
    # Check time and broker are correct
    if not auth_message['broker'] in valid_broker_hosts:
        return False
    utc_datetime = timegm(gmtime())/60 # unixtime in minutes
    supplied_datetime = int(auth_message['time'])
    time_delta = supplied_datetime - utc_datetime
    if (time_delta > 3) or (time_delta < -3): # 6 minute window to allow for plenty of clock skew
        return False
    # If they made it this far they are authenticated
    return True

def acl_check(clientid, username, topic, access):
    if access == mosquitto_auth.MOSQ_ACL_READ:
        if mosquitto_auth.topic_matches_sub('mesh/+/user/' + username + '/inbox', topic): # user reading their own inbox
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/+/user/+/profile', topic): # user reading another users profile
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/+/user/+/directory', topic): # user reading another users directory entry
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/+/user/+/key', topic): # user reading another users keyblock
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/+/user/+/items', topic): # user reading another users items
            return True
        elif mosquitto_auth.topic_matches_sub('$SYS/broker/clients/total', topic): # make the total number of users visible
            return True
        elif mosquitto_auth.topic_matches_sub('broker/*', topic): # users may read any broker broadcast messages
            return True
        elif mosquitto_auth.topic_matches_sub('peers', topic): # users may read any broker peer message
            return True
    elif access == mosquitto_auth.MOSQ_ACL_WRITE:
        if mosquitto_auth.topic_matches_sub('mesh/local/user/+/inbox', topic): # user sending a message
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/local/user/' + username + '/items', topic): # user updating their own items
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/local/user/' + username + '/profile', topic): # user updating their own profile
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/local/user/' + username + '/directory', topic): # user updating their own directory entry
            return True
        elif mosquitto_auth.topic_matches_sub('mesh/local/user/' + username + '/key', topic): # user updating their own keyblock
            return True
        elif mosquitto_auth.topic_matches_sub('broker/*', topic) and username == broker_key : # broker operator setting broadcast messages
            return True  
        elif mosquitto_auth.topic_matches_sub('peers', topic) and username == broker_key : # broker operator can modify MQTT mesh peers
            return True 
    # Default is to deny access unless an ACL above is explicitly matched
    return False
