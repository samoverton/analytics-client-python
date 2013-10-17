Analytics python client (Beta)
==============================

Create tables and cubes, insert data and query aggregates with Python!


Requirements
============

Python 2.6+


Installation
============

```
sudo python setup.py install
```

Sample code:
============

```
#!/usr/bin/python2.6

from acunu import analytics
import random

host='bunnie'
table_name = "test_table"

print 'open session'
target = analytics.Node('http://' + host + ':8080')
session = target.getSession()

print 'setup table'
session.execute('drop table if exists ' + table_name)
session.execute('create table ' + table_name + ' (user string, val long)')
session.execute('create cube count from ' + table_name + ' group user')

print 'insert events'
names = ['aaron', 'ah', 'alexandra', 'alver', 'ana', 'andrea']
events_count = 500

inserter = session.getInserter(table_name)
try:
    for i in range(1,events_count+1):
        event = dict()
        event['val'] = random.randrange(1,10)
        event['user'] = random.choice(names)
        inserter.send(event)
    print "flush inserter"
    inserter.flush()
finally:
    inserter.close()

print 'submit query'
result = session.execute('select count from ' + table_name + ' group by user')
print result.getRows()
```
