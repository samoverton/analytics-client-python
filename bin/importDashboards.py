#!/usr/bin/python2.6

## loads dashboards in a human-friendly json form into cql
## for now you have to have opened the ui for this script to work (doesnt create keyspaces or cfs)

import sys
import json
import uuid
from operator import itemgetter

from acunu import analytics

from optparse import OptionParser


def contains(list, filter):
    for x in list:
        if filter(x):
            return True
    return False


# json unicode conversion fn from http://stackoverflow.com/questions/956867/how-to-get-string-objects-instead-unicode-ones-from-json-in-python
def convert(input):
    if isinstance(input, dict):
        return dict([(convert(key), convert(value)) for key, value in input.iteritems()])
    elif isinstance(input, list):
        return [convert(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input


def loads(s):
    return convert(json.loads(s))


def init(host, port, verbose):
    node = analytics.Node('http://{0}:{1}'.format(host, port))
    session = node.getSession()
    if verbose:
        print 'checking for dashboards table'
    schema = session.getSchema()

    tables = schema.getTables()
    if not 'dashboardProperties' in tables:
        session.execute('create table dashboardProperties (ty STRING, k STRING, v STRING) properties hidden=true;')

        session.execute('create cube ID(v) where k;')
        session.execute('create cube ID(v) where ty group by k;')

    return session


def restore(host, port, verbose):

    session = init(host, port, verbose)
    dashs = json.load(sys.stdin)
    if verbose:
        for d in dashs:
            print "found dashboard %s" % d
            for w in dashs[d]:
                print "\tfound widget %s" % w
    dashboards = []
    widgets = []
    for d in dashs:
        d_uuid = str(uuid.uuid4())
        widget_index = 0

        for w in d['widgets']:
            w['dashboardId'] = d_uuid
            w['sortOrder'] = widget_index
            w['id'] = str(uuid.uuid4())
            widgets.append(w)
            widget_index += 1

        d['id'] = d_uuid
        del d['widgets']
        dashboards.append(d)

    inserter = session.getInserter('dashboardProperties')

    for d in dashboards:
        inserter.send({'ty': '/user/api/dashboard', 'k': d['id'], 'v': json.dumps(d)})
    for w in widgets:
        inserter.send({'ty': '/user/api/widget', 'k': w['id'], 'v': json.dumps(w)})

    inserter.flush()


def backup(host, port, verbose):
    session = init(host, port, verbose)
    dashboards = {}

    def remove_empties(rows):
        return filter(lambda r: len(r[1]) > 0, rows)

    def without_fields(obj, fields):
        for f in fields:
            del obj[f]
        return obj

    dashs = map(lambda d_row: loads(d_row[1]), remove_empties(session.execute("SELECT v FROM dashboardProperties WHERE ty='/user/api/dashboard' GROUP BY k").getRows()))

    for d in dashs:
        id = d['id']
        dashboards[id] = without_fields(d, ['id', ])
        dashboards[id]['widgets'] = []

    widgets = map(lambda w_row: loads(w_row[1]), remove_empties(session.execute("SELECT v FROM dashboardProperties WHERE ty='/user/api/widget' GROUP BY k").getRows()))

    for w in sorted(widgets, key=itemgetter('sortOrder')):
        if verbose:
            print 'loading widget %s' % w['id']

        dashboards[w['dashboardId']]['widgets'].append(without_fields(w, ['id', 'sortOrder', 'dashboardId']))

    print json.dumps(dashboards.values(), sort_keys=True, indent=4)


def clean(host, port, verbose):
    session = init(host, port, verbose)
    session.execute('truncate table dashboardProperties;')


version = 0.2
if __name__ == '__main__':
    parser = OptionParser(usage='%prog --host vm --mode [backup|restore|clean|init] --verbose', version=('%%prog %s' % version))
    parser.add_option('--host', dest='host', help='jbird host (default=localhost)', default='localhost', metavar='HOST')
    parser.add_option('--port', dest='port', help='jbird port (default=8080)', default=8080, metavar='PORT')
    parser.add_option('--mode', dest='mode', help='mode: backup/restore/clean/init', metavar='MODE')
    parser.add_option('--verbose', dest='verbose', help='be chatty', action='store_true', metavar='VERBOSE')
    options, _ = parser.parse_args()
    if options.mode == 'restore':
        restore(options.host, options.port, options.verbose)
    elif options.mode == 'backup':
        backup(options.host, options.port, options.verbose)
    elif options.mode == 'clean':
        clean(options.host, options.port, options.verbose)
    elif options.mode == 'init':
        init(options.host, options.port, options.verbose)
    else:
        raise Exception('unknown mode \'%s\'' % options.mode)
