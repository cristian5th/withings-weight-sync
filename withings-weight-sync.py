#!/usr/bin/env python3
"""
Withings Health to Garmin Connect Weight Updater
"""

__author__ = "Jacco Geul"
__version__ = "0.1.0"
__license__ = "GPLv3"

from optparse import OptionParser
import configparser
from fit import FitEncoder_Weight
from garmin import GarminConnect
from smashrun import Smashrun
from oauthlib.oauth2 import MobileApplicationClient
import urllib.parse
import withings
import os.path
import sys
import time
import getpass
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import ssl

withings_auth_code = None

# Extremely basic HTTP server for handling authorization response
class AuthorizationRepsponseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global withings_auth_code
        withings_auth_code = parse_qs(urlparse(self.path).query).get('code', None)[0]
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write('<html><body><h1>Authorization successful!</h1></body></html>'.encode('utf-8'))

# Do command processing
class MyParser(OptionParser):
    def format_epilog(self, formatter):
        return self.epilog

usage = "usage: %prog [options] command [service]"
epilog = """
Commands:
  setup, sync, last, userinfo, subscribe, unsubscribe, list_subscriptions

Services:
  withings, garmin, smashrun, smashrun_code (setup only)

Copyright (c) 2018 by Jacco Geul <jacco@geul.net>
Licensed under GNU General Public License 3.0 <https://github.com/magnific0/nokia-weight-sync/LICENSE>
"""
parser = MyParser(usage=usage,epilog=epilog,version=__version__)

parser.add_option('-k', '--key', dest='key', help="Key/Username")
parser.add_option('-s', '--secret', dest='secret', help="Secret/Password")
parser.add_option('-u', '--callback', dest='callback', help="Callback/redirect URI")
parser.add_option('-a', '--authorization-server', dest='auth_serv', action="store_true", default=None, help="Authorization server")
parser.add_option('-c', '--config', dest='config', default='config.ini', help="Config file")

(options, args) = parser.parse_args()

if len(args) == 0:
    print("Missing command!")
    print("Available commands: setup, sync, last, userinfo, subscribe, unsubscribe, list_subscriptions")
    sys.exit(1)

command = args.pop(0)

config = configparser.ConfigParser()
config.read(options.config)

# Decode the Garmin password
if config.has_section('garmin'):
    if config.has_option('garmin', 'password'):
        config.set('garmin', 'password', base64.b64decode(config.get('garmin', 'password').encode('ascii')).decode('ascii'))

def setup_withings( options, config ):
    """ Setup the Withings Health API
    """
    global withings_auth_code
    if options.key is None:
        print("To set a connection with Withings Health you must have registered an application at https://account.withings.com/partner/add_oauth2 .")
        options.key = input('Please enter the client id: ')

    if options.secret is None:
        options.secret = input('Please enter the consumer secret: ')

    if options.callback is None:
        options.callback = input('Please enter the callback url known by Withings: ')

    if options.auth_serv is None:
        auth_serv_resp = input('Spin up HTTP server to automate authorization? [y/n] : ')
        if auth_serv_resp == 'y':
            options.auth_serv = True
        else:
            options.auth_serv = False

    if options.auth_serv:
        callback_parts = urlparse(options.callback)
        httpd_port = callback_parts.port
        httpd_ssl = callback_parts.scheme == 'https'
        if not httpd_port:
            httpd_port = 443 if httpd_ssl else 80
        certfile = None
        if httpd_ssl and not certfile:
            print("Your callback url is over https, but no certificate is present.")
            print("Change the scheme to http (also over at Withings!) or specify a certfile above.")
            exit(0)

    auth = withings.WithingsAuth(options.key, options.secret, options.callback)
    authorize_url = auth.get_authorize_url()
    print("Visit: %s\nand select your user and click \"Allow this app\"." % authorize_url)

    if options.auth_serv:
        httpd = HTTPServer(('', httpd_port), AuthorizationRepsponseHandler)
        if httpd_ssl:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=certfile, server_side=True)
        httpd.socket.settimeout(100)
        httpd.handle_request()
    else:
        print("After redirection to your callback url find the authorization code in the url.")
        print("Example: https://your_original_callback?code=abcdef01234&state=XFZ")
        print("         example value to copy: abcdef01234")
        withings_auth_code = input('Please enter the authorization code: ')
    creds = auth.get_credentials(withings_auth_code)

    if not config.has_section('withings'):
        config.add_section('withings')

    config.set('withings', 'consumer_key', options.key)
    config.set('withings', 'consumer_secret', options.secret)
    config.set('withings', 'callback_uri', options.callback)
    config.set('withings', 'access_token', creds.access_token)
    config.set('withings', 'token_expiry', creds.token_expiry)
    config.set('withings', 'token_type', creds.token_type)
    config.set('withings', 'refresh_token', creds.refresh_token)
    config.set('withings', 'user_id', creds.user_id)

def setup_garmin( options, config ):
    """ Setup the Garmin Connect credentials
    """

    if options.key is None:
        options.key = input('Please enter your Garmin Connect username: ')

    if options.secret is None:
        options.secret = getpass.getpass('Please enter your Garmin Connect password: ')

    # Test out our new powers
    garmin = GarminConnect()
    session = garmin.login(options.key, options.secret)

    if not config.has_section('garmin'):
        config.add_section('garmin')

    config.set('garmin', 'username', options.key)
    config.set('garmin', 'password', options.secret)

def setup_smashrun( options, config ):
    """ Setup Smashrun API implicit user level authentication
    """
    mobile = MobileApplicationClient('client') # implicit flow
    client = Smashrun(client_id='client',client=mobile,client_secret='my_secret',redirect_uri='https://httpbin.org/get')
    auth_url = client.get_auth_url()
    print("Go to '%s' and log into Smashrun. After redirection, copy the access_token from the url." % auth_url[0])
    print("Example url: https://httpbin.org/get#access_token=____01234-abcdefghijklmnopABCDEFGHIJLMNOP01234567890&token_type=[...]")
    print("Example access_token: ____01234-abcdefghijklmnopABCDEFGHIJLMNOP01234567890")
    token = input("Please enter your access token: " )
    if not config.has_section('smashrun'):
        config.add_section('smashrun')
    config.set('smashrun', 'token', urllib.parse.unquote(token))
    config.set('smashrun', 'type', 'implicit')

def setup_smashrun_code( options, config ):
    """ Setup Smashrun API explicit code flow (for applications)
    """
    if options.key is None:
        print("To set a connection with Smashrun you need to request an API key at https://api.smashrun.com/register .")
        options.key = input('Please the client id: ')

    if options.secret is None:
        options.secret = input('Please enter the client secret: ')

    client = Smashrun(client_id=options.key,client_secret=options.secret,redirect_uri='urn:ietf:wg:oauth:2.0:auto')
    auth_url = client.get_auth_url()
    print("Go to '%s' and authorize this application." % auth_url[0])
    code = input('Please enter your the code provided: ')
    resp = client.fetch_token(code=code)

    if not config.has_section('smashrun'):
        config.add_section('smashrun')

    config.set('smashrun', 'client_id', options.key)
    config.set('smashrun', 'client_secret', options.secret)
    config.set('smashrun', 'refresh_token', resp['refresh_token'])
    config.set('smashrun', 'type', 'code')

def save_config():
    # Encode the Garmin password
    if config.has_section('garmin'):
        if config.has_option('garmin', 'password'):
            config.set('garmin', 'password', base64.b64encode( config.get('garmin', 'password').encode('ascii') ).decode('ascii'))

    # New Withings tokens (if refreshed)
    if client_withings:
        creds = client_withings.get_credentials()
        if config.get('withings', 'access_token') != creds.access_token:
            config.set('withings', 'access_token', creds.access_token)
            config.set('withings', 'token_expiry', creds.token_expiry)
            config.set('withings', 'refresh_token', creds.refresh_token)

    with open(options.config, 'w') as f:
        config.write(f)
        f.close()

    print("Config file saved to %s" % options.config)

def auth_withings( config ):
    """ Authenticate client with Withings Health
    """
    creds = withings.WithingsCredentials(config.get('withings', 'access_token'),
                                   config.get('withings', 'token_expiry'),
                                   config.get('withings', 'token_type'),
                                   config.get('withings', 'refresh_token'),
                                   config.get('withings', 'user_id'),
                                   config.get('withings', 'consumer_key'),
                                   config.get('withings', 'consumer_secret')
                                   )
    client = withings.WithingsApi(creds)
    return client

def auth_smashrun( config ):
    """ Authenticate client with Smashrun
    """

    if config.get('smashrun', 'type') == 'code':
        client = Smashrun(client_id=config.get('smashrun', 'client_id'),
                        client_secret=config.get('smashrun', 'client_secret'))
        client.refresh_token(refresh_token=config.get('smashrun', 'refresh_token'))
    else:
        mobile = MobileApplicationClient('client') # implicit flow
        client = Smashrun(client_id='client', client=mobile,
                        token={'access_token':config.get('smashrun', 'token'),'token_type':'Bearer'})
    return client

client_withings = None
if command != 'setup':
    client_withings = auth_withings( config )

if command == 'setup':

    if len(args) == 1:
        service = args[0]
    else:
        print("You must provide the name of the service to setup. Available services are: withings, garmin, smashrun, smashrun_code.")
        sys.exit(1)

    if service == 'withings':
        setup_withings( options, config )
    elif service == 'garmin':
        setup_garmin( options, config )
    elif service == 'smashrun':
        setup_smashrun( options, config )
    elif service == 'smashrun_code':
        setup_smashrun_code( options, config )
    else:
        print('Unknown service (%s), available services are: withings, garmin, smashrun, smashrun_code.')
        sys.exit(1)

elif command == 'userinfo':
    print(client_withings.get_user())

elif command == 'last':
    m = client_withings.get_measures(limit=1)[0]

    print(m.date)
    if len(args) == 1:
        types = dict(withings.WithingsMeasureGroup.MEASURE_TYPES)
        print(m.get_measure(types[args[0]]))
    else:
        for n, t in withings.WithingsMeasureGroup.MEASURE_TYPES:
            print("%s: %s" % (n.replace('_', ' ').capitalize(), m.get_measure(t)))

elif command == 'lastn':
    if len(args) != 1:
        print("You must supply the number of measurement groups to fetch.")
        sys.exit(1)

    # Get n last measurements
    mall = client_withings.get_measures(limit=args[0])

    for n, m in enumerate(mall):
        # Print clear header and date for each group
        print("--Group %i" % n)
        print(m.date)

        # Print all types one by one
        for n, t in withings.WithingsMeasureGroup.MEASURE_TYPES:
            print("%s: %s" % (n.replace('_', ' ').capitalize(), m.get_measure(t)))
        print("")

elif command == 'sync-preview':
    if len(args) == 1:
        service = args[0]
    else:
        print("You must provide the name of the service to sync. Available services are: garmin, smashrun.")
        sys.exit(1)

    # Get next measurements
    last_sync = int(config.get(service,'last_sync')) if config.has_option(service, 'last_sync') else 0
    mall = client_withings.get_measures(lastupdate=last_sync)

    for n, m in enumerate(mall):
        # Print clear header and date for each group
        print("--Group %i" % n)
        print(m.date)

        # Print all types one by one
        for n, t in withings.WithingsMeasureGroup.MEASURE_TYPES:
            print("%s: %s" % (n.replace('_', ' ').capitalize(), m.get_measure(t)))
        print("")

elif command == 'sync':

    if len(args) == 1:
        service = args[0]
    else:
        print("You must provide the name of the service to sync. Available services are: garmin, smashrun.")
        sys.exit(1)

    # Get next measurements
    last_sync = int(config.get(service,'last_sync')) if config.has_option(service, 'last_sync') else 0
    groups = client_withings.get_measures(lastupdate=last_sync)
    types = dict(withings.WithingsMeasureGroup.MEASURE_TYPES)

    if len(groups) == 0:
        print("Their is no new measurement to sync.")
        save_config()
        sys.exit(0)

    if service == 'garmin':

        next_sync = int(time.mktime(groups[-1].date.timetuple()))

        # Do not repeatidly sync the same value
        if next_sync == last_sync:
            print('Last measurement was already synced')
            save_config()
            sys.exit(0)

        # Get height for BMI calculation
        height = None
        m = client_withings.get_measures(limit=1, meastype=types['height'])
        if len(m):
            height = m[0].get_measure(types['height'])

        # create fit file
        fit = FitEncoder_Weight()
        fit.write_file_info()
        fit.write_file_creator()
        fit.write_device_info(device_timestamp=next_sync)
        for m in groups:
            weight = m.get_measure(types['weight'])
            water = m.get_measure(types['hydration']);
            water_percent = None
            if weight:
                bmi = None
                if height:
                    bmi = round(weight / pow(height, 2), 1)
                if water:
                    water_percent = round(water / weight * 100, 1)

                fit.write_weight_scale(weight_timestamp=int(time.mktime(m.date.timetuple())), weight=weight, percent_fat=m.get_measure(types['fat_ratio']),
                    percent_hydration=water_percent, bone_mass=m.get_measure(types['bone_mass']), muscle_mass=m.get_measure(types['muscle_mass']),
                    bmi=bmi)

        fit.finish()

        garmin = GarminConnect()
        session = garmin.login(config.get('garmin','username'), config.get('garmin','password'))
        r = garmin.upload_file(fit.getvalue(), session)
        if r:
            print("%d weights has been successfully updated to Garmin!" % (len(groups)))
            config.set('garmin','last_sync', str(next_sync))

    elif service == 'smashrun':

        for m in reversed(groups):
            t = types['weight']
            weight = m.get_measure(t)
            if weight:
                break

        print("Last weight from Withings Health: %s kg taken at %s" % (weight, m.date))


        # Do not repeatidly sync the same value
        if config.has_option('smashrun', 'last_sync'):
            if m.date.timestamp == int(config.get('smashrun','last_sync')):
                print('Last measurement was already synced')
                save_config()
                sys.exit(0)

        client_smashrun = auth_smashrun( config )

        resp = client_smashrun.create_weight( weight, m.date.format('YYYY-MM-DD') )

        if resp.status_code == 200:
            print('Weight has been successfully updated to Smashrun!')
            config.set('smashrun','last_sync', str(m.date.timestamp))

    else:
        print('Unknown service (%s), available services are: withings, garmin, smashrun')
        save_config()
        sys.exit(1)

elif command == 'subscribe':
    client_withings.subscribe(args[0], args[1])
    print("Subscribed %s" % args[0])

elif command == 'unsubscribe':
    client_withings.unsubscribe(args[0])
    print("Unsubscribed %s" % args[0])

elif command == 'list_subscriptions':
    l = client_withings.list_subscriptions()
    if len(l) > 0:
        for s in l:
            print(" - %s " % s['comment'])
    else:
        print("No subscriptions")

else:
    print("Unknown command")
    print("Available commands: setup, sync, sync-preview, last, userinfo, subscribe, unsubscribe, list_subscriptions")
    sys.exit(1)

save_config()
sys.exit(0)
