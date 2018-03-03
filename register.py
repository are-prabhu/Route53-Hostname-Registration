#!/usr/bin/env python3
"""Client for automagical registration of hostname into Route53 dns.

Usage:
  register <role> [<alias>]... [options]
  register (-h | --help)
  register --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --one-shot    Run once and exit.
  --debug       Enable debug mode
  --safe        Print but don't actually delete any queues.
"""

"""
TODO: This might be a terrible lies.
    1) Need to find better logic for record_register.
    2) Use only boto or boto3 not both.
    3) Refine the client.

ENHANCEMENT: 
    1) Improve the script to perform deregistration.
    2) Enhance to support differnt DBs
"""



from boto.route53.connection import Route53Connection
from boto.route53.record import ResourceRecordSets
from docopt import docopt
import boto3
import boto.utils
import botocore.session
import logging
import netifaces
import os
import socket
import string
import subprocess
import sys
import redis
import time
import six

# Constants
__version__ = '1.0.0'
REDIS_TTL = 120
REDIS_REFRESH = REDIS_TTL / 3
EC2_UPDATE_INTERVAL = 180  # Seconds.
SUFFIX_SEPERATOR = '/'
REDISHOST="172.17.0.2"


route53 = Route53Connection()
client = boto3.client('route53')
conn = boto.connect_route53()
results = route53.get_all_hosted_zones()
hostedrecord='blog.truekall.com'


# Arg parsing.
arguments = docopt(__doc__, version=__version__)
if arguments['--debug'] or arguments['--one-shot']:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)
logging.getLogger('boto').setLevel(logging.INFO)
LOG.debug("Arguments: %s", arguments)

# What's my IP?
for ifname in netifaces.interfaces():
    if ifname == 'lo':
        continue
    else:
        try:
            localIP = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
            LOG.debug("Using %s IP: %s", ifname, localIP)
            break
        except KeyError:
            pass
else:
    LOG.error("No IP address found. Exiting.")
    sys.exit(1)

def string_gen(characters):
    """Generate an infinite series of strings 'a' .. 'zzz'."""
    def int_to_string(i, chars):
        """
        Turn an integer into a string.

        >>> int_to_string(0)
        a
        >>> int_to_string(25)
        z
        >>> int_to_string(26)
        aa
        >>> int_to_string(50)
        ax
        """
        l = len(chars)
        acc = ''
        while i is not None:
            acc += chars[i % l]
            if i < l:
                i = None
            else:
                i = (i/l)-1
        acc = list(acc)
        acc.reverse()
        acc = ''.join(acc)
        return acc

    x = 0
    while True:
        yield int_to_string(x, characters)
        x += 1


def hostname_set(name):
    """Update the local hostname."""
    if socket.gethostname() == name:
        LOG.info("No need to update hostname, it is already correct.")
        return None

    LOG.warning("Updating hostname to: %s.", name)
    if os.path.exists('/usr/bin/hostnamectl'):
        LOG.info("Using hostnamectl to set-hostname to %s", name)
        subprocess.check_call(['/usr/bin/hostnamectl', 'set-hostname', name])
    else:
        LOG.info("Writing name %s to /etc/hostname", name)
        with open('/etc/hostname', 'w') as f:
            f.write(name + '\n')
        subprocess.check_call(['/etc/init.d/hostname.sh', 'start'])

    # # Kick off a background highstate. (By restarting the minion.)
    # subprocess.check_call(['/usr/bin/sv', 'term', 'salt-minion'])


def redis_connection():
    """Return connection to Redis."""
    redis_db = redis.StrictRedis(host=REDISHOST, port=6379, db=0)
    return redis_db


def redis_ping(name, suffix, check=True):
    """Remind Redis that I exist."""
    r = redis_connection()
    key = SUFFIX_SEPERATOR.join((name, suffix))
    if check and r.get(key).decode("utf-8")  != localIP:
        LOG.error("Key %s no logner equals %s", key, localIP)
        raise RuntimeError("Somehow I no longer own my own name!")
    LOG.info("Updating TTL: %s", key)
    return r.set(key, localIP, ex=REDIS_TTL)


def redis_for_hostname(name):
    """
    Return the suffix this machine should use.

    If the host is already known, name will be reused, otherwise a new
    address will be assigned.
    """
    g = string_gen(string.ascii_lowercase)
    r = redis_connection()

    # Check if I'm already registered.
    ips = ips_for_hostname(name)
    if localIP in ips:
        return ips[localIP].rsplit(SUFFIX_SEPERATOR, 1)[1]

    # Generate a new entry
    while True:
        suffix = six.next(g)
        host = SUFFIX_SEPERATOR.join([name, suffix])
        LOG.debug("Trying to claim %s", host)
        result = r.set(host, localIP, nx=True, ex=REDIS_TTL)
        if result is True:
            LOG.debug("Claimed!")
            return suffix


def ips_for_hostname(name):
    """Return a dictionary of all the ip->hostnames for a given name."""
    r = redis_connection()
    print (r)
    names = r.keys(name + SUFFIX_SEPERATOR + '*')
    LOG.debug("Redis names for %s: %r", name, names)
    if len(names) == 0:
        LOG.debug("No names known in Redis. We're the first!")
        return dict()
    ips = r.mget(names)
    ip_dict = dict(zip(ips, names))
    LOG.debug("Redis IPs: %r", ip_dict)
    return ip_dict


def ec2_set_tags(instance_id=None, **kwargs):
    """
    Set the name and/or tags on a host in EC2.

    If instance_id is passed, it is used, otherwise defaults to self.
    """
    c = boto.connect_ec2()

    # Default to self.
    if instance_id is None:
        instance_id = boto.utils.get_instance_metadata()['instance-id']

    # Because AWS says the name tag is 'Name' not 'name'
    if 'Name' not in kwargs and 'name' in kwargs:
        kwargs['Name'] = kwargs.pop('name')

    # Purge keys that are already correct.
    tags = dict([
        (t.name, t.value) for t in ec2_get_tags(instance_id=instance_id)
    ])
    for k in tags.keys():
        if k in kwargs and kwargs[k] == tags[k]:
            del(kwargs[k])

    # Check if we still need to do anything.
    if len(kwargs) == 0:
        LOG.debug("All is as it should be, no update needed.")
        return True
    LOG.info("Updating EC2: %r", kwargs)
    return c.create_tags([instance_id], kwargs)

def credentials():
    return botocore.session.Session().get_credentials()

def ec2_get_tags(instance_id=None):
    """
    Return the name and/or tags on a host in EC2.

    If instance_id is passed, it is used, otherwise defaults to self.
    """
    c = boto.connect_ec2()
    if instance_id is None:
        instance_id = boto.utils.get_instance_metadata()['instance-id']
    return c.get_all_tags(filters={'resource-id': instance_id})

def dns_upsert_alias(name, zoneid, IP):
    """Dict for doing a DNS upsert."""
    domainname='.'.join(name.split('.')[-3:])
    all_records=[]
    for each_value in IP:
       all_records.append({ 'Value': each_value })

    dnsupsert = {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': name,
                        'Type': 'A',
                        'TTL': 20,
                        'ResourceRecords': all_records
                       
                    }
            }
    return dnsupsert

def record_register(name,IP):
    """ Consolidate DNS name and IP to upsert"""
    newname=name+'.'+ hostedrecord+'.'
    for zone in results['ListHostedZonesResponse']['HostedZones']:
        zonename=list(zone['Name'])[:-1]
        zonename=''.join(zonename)
        if hostedrecord == zonename:
            zone_id = zone['Id'].replace('/hostedzone/', '')
            recordSets=route53.get_zone(zonename)
            change_set = ResourceRecordSets(recordSets, zone_id)
            for recordset in recordSets.get_records():
                if recordset.name == newname:
                    if localIP != recordset.to_print():
                        upsert = dns_upsert_alias(newname,zone_id,[localIP])
                        response = client.change_resource_record_sets(
                                   HostedZoneId=zone_id,
                                   ChangeBatch={'Changes': [upsert]})
                else:
                    upsert = dns_upsert_alias(newname,zone_id,IP)
                    response = client.change_resource_record_sets(
                                HostedZoneId=zone_id,
                                ChangeBatch={'Changes': [upsert]})

def main(arguments):
    """Daemon loop to keep hostname current."""
    role = arguments['<role>']
    LOG.info("Starting up, registering self as member of: %s", role)
    suffix = redis_for_hostname(role)
    me = '-'.join((role, suffix))
    record_info=record_register(me,[localIP])
          
    LOG.info("My unique name is: %s", me)

    aliases = arguments['<alias>']
    if aliases:
        LOG.info("Also registering the following aliases: %s", aliases)

    ec2_update = None

    while True:
        redis_ping(role, suffix)
        for alias in aliases:
            redis_ping(alias, suffix, check=False)
        hostname_set(me)

        if (
            ec2_update is None
            or time.time() - ec2_update > EC2_UPDATE_INTERVAL
        ):
            LOG.debug('Updating EC2 (if needed).')
            ec2_set_tags(name=me, role=role)
            ec2_update = time.time()

        if arguments['--one-shot']:
            sys.exit(0)
        LOG.debug('Zzzzzz.....')
        time.sleep(REDIS_REFRESH)


if __name__ == '__main__':
    main(arguments)
