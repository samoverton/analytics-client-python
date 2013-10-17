"""
Acunu Analytics client library.
"""

from __future__ import division
import calendar
import json
import httplib
import urllib
from datetime import datetime
import threading
import time
import traceback
import logging
import abc

API_URI = '/analytics/api'
DEFAULT_PORT = 8080


logger = logging.getLogger(__name__)


class AnalyticsException(Exception):
    """
    Base exception class for everything explicitly raised by the client module.
    """
    pass


class TypeException(AnalyticsException):
    """
    Raised when unexpected parameter types are encountered, though `TypeErrors`
    may still occur instead.
    """
    pass


class HTTPErrorException(AnalyticsException):
    """
    Raised when a httplib request fails, or if a HTTP non-2** return code is
    received.
    """
    pass


class MalformedResult(AnalyticsException):
    """
    Raised when the object constructed from the json response
    does not conform to the expected format
    """
    pass


class Target(object):
    """
    This is an abstract class for Acunu Analytics target infrastructure (currently just single
    Nodes). This is an internal class.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def getSession(self, **kwargs):
        pass

    @abc.abstractmethod
    def checkState(self):
        pass

    @abc.abstractmethod
    def request(self, uri, method, body, params, headers):
        pass

    @abc.abstractmethod
    def getInserter(self, tableName, numConns, flushPeriod, bufferFlushThreshold):
        pass


class NodeException(AnalyticsException):
    """
    Base exception class for everything explicitly raised by the `Node` class.
    """
    pass


class NodeCreateException(NodeException):
    """
    Raised upon failure to initialise a `Node` object.
    """
    pass


class Node(Target):
    """
    Bind to an Acunu Analuytics node.
    """

    class _ConnectionWrapper(object):
        """
        A wrapper around (a) http(s) connection(s).
        """

        def __init__(self, nodeinfo):
            self.info = nodeinfo
            self.retries = 2
            self.conn = self.make()

        def request(self, uri, method, body, params, headers):
            """
            Send a raw HTTP request to analytics
            """
            if params is None:
                params = {}
            if headers is None:
                headers = {}
            if body is None:
                body = ''

            url = '%s%s' % (API_URI, uri)
            if params:
                if not isinstance(params, dict):
                    raise TypeException("Parameters should be specified as a dict")
                url = "%s%s%s" % (url, ("&" if "?" in url else "?"), urllib.urlencode(params))
                params = None
            if isinstance(body, dict) or isinstance(body, list):
                body = json.dumps(body)
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = len(body)
            elif isinstance(body, basestring):
                headers["Content-Length"] = len(body)

            retries_left = self.retries
            while True:
                logger.debug("Requesting: {0}, {1}, {2}, {3}".format(method, url, body, headers))
                self.conn.request(method, url, body, headers)
                try:
                    resp = self.conn.getresponse()
                    break
                except httplib.BadStatusLine, e:
                    time.sleep(0.5)
                    if retries_left == 0:
                        print "{0}:{1} - {2} / failed even after {3} retries".format(type(e), e, e.line, self.retries)
                        raise
                    # re-establish connection
                    logger.debug("{0}:{1} - {2} / remaking connection and then retrying".format(type(e), e, e.line))
                    self.conn = self.make()
                    retries_left -= 1

            if int(resp.status / 100) != 2:
                raise HTTPErrorException("HTTP Error (%d) on %s: %s" % (resp.status, uri, resp.read()))

            try:
                result = resp.read()
                return json.loads(result)
            except Exception:
                return None

        def make(self):
            """
            Make a single http/https connection for this node; this is merely a factory method,
            it does not alter the state of the `ConnectionWrapper` object in any way (in
            particular, the generated connection object is not added to the connection
            pool).

            :return a `httplib.HTTPConnection` or `httplib.HTTPSConnection` object
            """
            if 'http' == self.info['protocol'].lower():
                conn = httplib.HTTPConnection(self.info['hostname'], self.info['port'])
                logger.debug("Made http connection {0} for {1}".format(conn, self.info))
            elif 'https' == self.info['protocol'].lower():
                conn = httplib.HTTPSConnection(self.info['hostname'], self.info['port'], self.info['key_file'], self.info['cert_file'])
                logger.debug("Made https connection {0} for {1}".format(conn, self.info))
            return conn

    def init(self, hostname="localhost", port=DEFAULT_PORT, protocol='http', key_file=None, cert_file=None):
        recognised_protocols = ["http", "https"]
        self.info = dict()
        self.info['protocol'] = str(protocol).lower()
        if self.info['protocol'] not in recognised_protocols:
            raise NodeCreateException("Unrecognized protocol '{0}'".format(self.info['protocol']))
        self.info['hostname'] = str(hostname).lower()
        self.info['port'] = int(port)
        self.info['key_file'] = key_file
        self.info['cert_file'] = cert_file

        self.cw = Node._ConnectionWrapper(self.info)

    def __init__(self, host=None):
        """
        This built-in initializer can only be used for http connections; for https connections,
        call the `init` method.
        """
        if host:
            recognised_protocols = ["http"]

            if len(str(host).split(':')) > 3:
                raise NodeCreateException("Unrecognized format '{0}', expecting something like 'http://localhost:80/'".format(host))
            protocol = str(host).split(':')[0].lower()
            if protocol not in recognised_protocols:
                raise NodeCreateException("Unrecognized protocol '{0}' in argument '{1}'".format(protocol, host))
            hostname = str(host).split(':')[1].split('//')[1].lower()
            port = int(DEFAULT_PORT) if len(str(host).split(':')) < 3 else int(str(host).split(':')[2].split('/')[0])
            self.init(hostname=hostname, port=port, protocol=protocol)
        else:
            logger.warn("Object {0} created, but initialization deferred; don't forget to call {0}.init() method".format(self, self))

    def _makeConn(self, get_wrapper=False):
        """
        Make a http/https connection.

        :return a http or https connection
        """
        cw = Node._ConnectionWrapper(self.info)
        if get_wrapper:
            return cw
        else:
            return cw.make()

    def getSession(self, **kwargs):
        """
        Get a Session object attached to this Node.
        """
        return Session(self, **kwargs)

    def request(self, uri, method="GET", body=None, params=None, headers=None):
        """
        Make a http request to this Node.
        """
        return self.cw.request(uri, method, body, params, headers)

    def checkState(self):
        """
        Checks if the node seems to be up and running; returns nothing, raises an Exception
        if there are any problems.
        """
        logger.info("Checking state of connection to note {0}".format(self.info))
        conn = self._makeConn()
        method = "GET"
        url = "{0}/schema".format(API_URI)
        body = ''
        headers = {'Content-Length': 0, 'Content-Type': 'application/json'}

        try:
            logger.debug("Doing {0} on {1} with body {2} and headers {3} on node {4} using conn {5}".format(method, url, body, headers, self.info, conn))
            conn.request(method, url, body, headers)
            resp = conn.getresponse()
        except Exception, e:
            raise HTTPErrorException("Failed to do {0} on {1} with body {2} and headers {3} on node {4}, got exception {5}:{6}".format(method, url, body, headers, self.info, type(e), e))

        if int(resp.status / 100) != 2:
            raise HTTPErrorException("With {0} on {1} with body {2} and headers {3} on node {3}, got HTTP response code {5}".format(method, url, body, headers, self.info, resp.status))
        result = resp.read()
        json.loads(result)

    def getInserter(self, tableName, numConns, flushPeriod, bufferFlushThreshold):
        return ChunkStreamerPool(pool_size=int(numConns),
                                 host=self.info['hostname'],
                                 port=self.info['port'],
                                 endpoint='/analytics/api/data/{0}'.format(str(tableName)),
                                 periodic_flush_seconds=flushPeriod,
                                 buf_flush_threshold=bufferFlushThreshold,
                                 protocol=self.info['protocol'],
                                 key_file=self.info['key_file'],
                                 cert_file=self.info['cert_file'])


class ResultException(AnalyticsException):
    """
    Raised when attempting to fetch results from a `Result` object which contains results
    from a failed query. Also may be raised if explicitly enabled in the `getStatus`
    method.
    """
    pass


class Result(object):
    """
    Wrapper around results from Acunu Analytics.
    """

    def __init__(self, result):
        self._raw_result = result
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Got result: {0}".format(result))
        self.streaming = False  # one day...

        if isinstance(result, dict):
            self.status = result['status']
            self.query = result['query']
            self.result = result['results']

        elif isinstance(result, list):
            self.status = 'success'
            self.query = 'Unknown: since allowMulti set false'
            self.result = result

        else:
            raise MalformedResult('malformed response object : {0}'.format(result))

        if not self.getStatus():
            logger.error(self.summary())
        elif logger.isEnabledFor(logging.DEBUG):
            logger.debug(self.summary())

    def getStatus(self, raiseOnNonSuccess=False):
        """
        Returns True if the result for the associated query was success.
        """
        assert self.streaming is not True  # one day...
        if self.status.lower() != "success":
            if raiseOnNonSuccess:
                raise ResultException(self.summary())
            return False
        return True

    def getRowsGen(self):
        """
        Return results through a generator.
        """
        if not self.getStatus():
            raise ResultException(self.summary())
        else:
            for row in self.result:
                yield row

    def getRows(self):
        """
        Return results as a list.
        """
        return list(self.getRowsGen())

    def summary(self):
        """
        Returns a formatted string summarizing the result in format 'query -> (status)';
        useful for debugging purposes.
        """
        return "Query '{0}' -> ({1})".format(self.query, self.status)


class SessionException(AnalyticsException):
    """
    Base exception class for everything explicitly raised by the `Session` class.
    """
    pass


class SessionCreateException(SessionException):
    """
    Raised upon failure to initialise a `Session` object.
    """
    pass


class Session(object):
    """
    The main interface to Acunu Analytics; a Session object allows the execution of
    arbitrary AQL statements as well as efficient event ingest with the underlying Target
    from which this Session was spawned (through a `getSession` method).
    """

    default_config = {'MAX_CONN_PER_HOST': 4,
            'DEFAULT_FLUSH_PERIOD': 10.0,
            'DEFAULT_BUFFER_FLUSH_THRESHOLD': 1000}

    def __init__(self, target, **kwargs):
        self.config = Session.default_config.copy()
        logger.debug("Constructing session with kwargs: {0}".format(kwargs))
        for key, value in kwargs.iteritems():
            if key in kwargs.keys():
                self.config[key] = value
            else:
                raise SessionCreateException("Unrecognized option {0}={1}".format(key, value))
        logger.info("Creating session with info: {0}".format(self.config))
        if not isinstance(target, Target):
            raise SessionCreateException("Unrecognized target type {0}".format(type(target)))
        self.target = target
        self.target.checkState()

    def execute(self, aqlStatement, **kwargs):
        """
        Execute some arbitrary AQL statement.
        """
        aql = str(aqlStatement)
        failOnError = kwargs.get('failOnError', True)
        logger.info("Executing '{0}' with params {1}".format(aql, kwargs))
        params = {"allowMulti": "true"}
        params.update(kwargs)
        headers = {"Accept": "application/json"}
        rawResults = self.target.request("/aql", "POST", aql, params, headers)

        if params['allowMulti'] == 'false':
            result = Result(rawResults)
            result.getStatus(failOnError)
            return result
        else:
            results = list()
            for result in rawResults:
                results.append(Result(result))
            if len(results) == 1:
                results[0].getStatus(failOnError)
                return results[0]
            else:
                for result in results:
                    result.getStatus(failOnError)
                return results

    def insert(self, tableName, event):
        dataUri = '/data/' + str(tableName)
        return self.target.request(uri=dataUri, method="POST", body=event)

    def getInserter(self, tableName, numConns=None, flushPeriod=None, bufferFlushThreshold=None):
        """
        Get an efficient batching, streaming interface through which to send events to the Analytics
        server.

        :param tableName: table to insert events into
        :param numConns: number of concurrent http connections to use (default: MAX_CONN_PER_HOST
                         specified during Session initialization.
        :param flushPeriod: number of seconds between background flushes (default: DEFAULT_FLUSH_PERIOD,
                        values of None will will disable creation of a flush thread for this inserter)
        :param bufferFlushThreshold: number of bytes before flushing
                                (default: DEFAULT_BUFFER_FLUSH_THRESHOLD)
        """
        if numConns is None:
            numConns = self.config['MAX_CONN_PER_HOST']
        if flushPeriod is None:
            flushPeriod = self.config['DEFAULT_FLUSH_PERIOD']
        if bufferFlushThreshold is None:
            bufferFlushThreshold = self.config['DEFAULT_BUFFER_FLUSH_THRESHOLD']

        return self.target.getInserter(tableName, numConns, flushPeriod, bufferFlushThreshold)

    def getSchema(self):
        """
        Get a Schema object reflecting the Acunu Analytics schema of this Session's target.
        """
        return Schema(self)


class SchemaException(AnalyticsException):
    """
    Raised upon any unexpected interaction with a `Schema` object (e.g. when requesting a
    non-existent table).
    """
    pass


class Schema(object):
    """
    A representation of the schema in some session.
    """

    def __init__(self, session):
        self.session = session
        self.refresh()

    def refresh(self):
        """
        Refresh the schema data from the Acunu Analytics server.
        """
        method = "GET"
        uri = "/schema"
        body = {}
        headers = {'Content-Length': 0, 'Content-Type': 'application/json'}
        self.rawSchema = self.session.target.request(method=method, uri=uri, body=body, headers=headers)

    def getTables(self, refresh=True):
        """
        Return the raw schema data.
        """
        if refresh:
            self.refresh()
        tables = list()
        for table in self.rawSchema:
            tables.append(table)
        return tables

    def getTable(self, tableName):
        """
        Return a Table object representing a particular table.
        """
        self.refresh()
        tables = self.getTables(refresh=False)
        if tableName not in tables:
            raise SchemaException("Cannot find table '{0}'; candidates are {1}".format(tableName, tables))

        return Table(tableName, self.rawSchema)


class Table(object):
    """
    A representation of a table from some underlying schema.
    """

    def __init__(self, tableName, schema):
        self.tableSchema = schema[tableName]

    def getName(self):
        return self.tableSchema['name']

    def getVersion(self):
        return self.tableSchema['version']

    def getProperty(self, property):
        return self.tableSchema['properties'][property]

    def getFields(self):
        fields = list()
        for field in self.tableSchema['data']:
            fieldTuple = (field['name'], field['type'])
            fields.append(fieldTuple)
        return fields


class Timestamp(object):
    """
    Converts time from different formats to datetime and can print in
    milliseconds.
    """
    formats = ['%H:%M:%S', '%Y-%m-%d', '%Y-%m-%d %H:%M:%S']

    def __init__(self, rawtime):
        """
        rawtime could be one of the 4 formats
            - an instance of datetime
            - time in string in formats = ['%H:%M:%S', '%Y-%m-%d', '%Y-%m-%d %H:%M:%S']
        """
        if isinstance(rawtime, datetime):
            self.time = rawtime
        else:
            for f in Timestamp.formats:
                try:
                    self.time = datetime.strptime(rawtime, f)
                    break
                except ValueError:
                    pass

        # format string has no date component - could break if the timestamp is 1900 forrealsies!
        if self.time.year == 1900:
            self.time = datetime.combine(datetime.now().date(), self.time.time())

    def __str__(self):
        """POSIX timestamp in milli seconds"""
        return str(calendar.timegm(self.time.timetuple()) * 1000)


class TimeRange(object):
    def __init__(self, start_time, end_time):
        self.start_time = start_time
        self.end_time = end_time

    def __str__(self):
        return ('[' + str(Timestamp(self.start_time)) + ','
                    + str(Timestamp(self.end_time)) + ']')

    def tostring(self):
        return '%s to %s' % (self.start_time, self.end_time)


class ChunkStreamerPoolException(AnalyticsException):
    """
    Raised upon any non-retry-able error in a `ChunkStreamerPool` object.
    """
    pass


class ChunkStreamerPool():
    """
    A wrapper on top of a pool of chunkStreamer objects. Error recovery is problematic with this;
    use with caution (especially when inserting into non-idempotent tables). A failure of any
    chunkStreamer in the pool requires the entire pool to be discarded.
    """

    def __init__(self, pool_size, host, port, endpoint, periodic_flush_seconds,
            buf_flush_threshold, protocol='http', key_file=None, cert_file=None):
        """
        Most arguments are direct pass-through to the chunkStreamer ctor, except for pool_size which
        specifies the number of chunkStreamer objects to instantiate in the pool.
        """

        assert pool_size >= 1, "pool_size argument must be >= 1."
        self.pool_size = pool_size
        self.rr_counter = 0
        self.err = False
        self.streamers = []
        for i in range(0, pool_size):
            streamer = chunkStreamer(host=host,
                                     port=port,
                                     endpoint=endpoint,
                                     buf_flush_threshold=buf_flush_threshold,
                                     periodic_flush_seconds=periodic_flush_seconds,
                                     protocol=protocol,
                                     key_file=key_file,
                                     cert_file=cert_file)
            logger.debug("{0!r} pool append {1!r}".format(self, streamer))
            self.streamers.append(streamer)

    def send(self, event):
        """
        Send over one of the chunkStreamer objects in the pool, with round-robin selection.
        """
        if self.streamers is None:
            raise ChunkStreamerPoolException("No ChunkStreamers in {0!r}; was it already closed?".format(self))

        if self.err:
            raise ChunkStreamerPoolException("{0!r} already compromised by an error; destroy and make a new one.".format(self))

        try:
            self.streamers[self.rr_counter].send(event)
            self.rr_counter = (self.rr_counter + 1) % self.pool_size
        except Exception:
            logger.exception('Error whilst trying to send event: {0}'.format(event))
            self.err = True
            raise

    def flush(self, check_reply=False):
        """
        Flush all chunkStreamer objects in the pool.
        """
        if self.streamers is None:
            raise ChunkStreamerPoolException("No ChunkStreamers in {0!r}; was it already closed?".format(self))

        if self.err:
            raise ChunkStreamerPoolException("{0!r} already compromised by an error; destroy and make a new one.".format(self))

        try:
            if self.streamers:
                for streamer in self.streamers:
                    streamer.flush(check_reply)
            else:
                logger.warn('Trying to flush but streamers are : {0}, so doing nothing.'.format(self.streamers))
        except Exception:
            logger.exception('Error whilst trying to flush ChunkStreamer: {0!r}'.format(streamer))
            self.err = True
            raise

    def close(self):
        """
        Close all streams.
        """
        if self.streamers is None:
            raise ChunkStreamerPoolException("No ChunkStreamers in {0!r}; was it already closed?".format(self))

        if self.err:
            method = chunkStreamer.abort
        else:
            method = chunkStreamer.close

        try:
            if self.streamers:
                while len(self.streamers) > 0:
                    cur_streamer = self.streamers[0]
                    method(cur_streamer)
                    self.streamers.pop(0)

        except Exception:
            logger.exception('Error whilst trying to close ChunkStreamer: {0!r}'.format(cur_streamer))
            # Forcibly close the remaining streamers
            for streamer in self.streamers:
                try:
                    streamer.abort()
                except:
                    pass

            self.err = True
            raise
        finally:
            self.streamers = None

    def _representation(self, repr_func):
        return '''<{0} at {1} rr_counter: {2}, err: {3}, pool_size: {4}, streamers: [{5}]>'''.format(
                self.__class__,
                hex(id(self)),
                self.rr_counter,
                self.err,
                self.pool_size,
                ', '.join(map(repr_func, self.streamers if self.streamers else [])),
                )

    def __repr__(self):

        return self._representation(repr)

    def __str__(self):
        return self._representation(str)

    def __enter__(self):
        logger.info("returning {0!s}".format(self))
        return self

    def __exit__(self, type, value, tb):
        if type is not None or value is not None or tb is not None:
            logger.warn("closing {0!s} with exception {1}:{2}\n{3}".format(self, type, value, traceback.format_exc()))
        logger.info("closing {0!s}".format(self))
        self.close()

    def __del__(self):
        if not self.err and self.streamers:
            self.close()


class ChunkStreamerException(AnalyticsException):
    """
    Raised upon any non-retry-able error in a `ChunkStreamer` object.
    """
    pass


class chunkStreamer():
    """
    Buffer and stream through chunked encoding. Warning: this currently uses httplib internally,
    which has all sorts of limitations (but is portable).
    """

    def __init__(self, host, port, endpoint, buf_flush_threshold, periodic_flush_seconds, protocol='http', key_file=None, cert_file=None, retries=1):
        """
        Set up http connection, and optionally create a periodic flush thread. Set
        periodic_flush_seconds to None to disable creation of a the periodic flush thread.
        """
        self.host = str(host)
        self.port = int(port)
        self.endpoint = str(endpoint)
        self.buf_flush_threshold = int(buf_flush_threshold)
        self.stream_buffer = ''
        self.last_flush_time = 0
        self.mutex = threading.Lock()
        self.run_flush_thread = False
        self._flush_thread = None
        self.closed = False
        self.opened = False
        self.protocol = protocol
        self.key_file = key_file
        self.cert_file = cert_file
        self.retries = retries
        self.periodic_flush_seconds = float(periodic_flush_seconds) if periodic_flush_seconds is not None else periodic_flush_seconds

        self._open_connection()

        if self.periodic_flush_seconds is not None:
            self._flush_thread = threading.Thread(target=self._periodic_flush_thread, args=(self.periodic_flush_seconds,))
            self.run_flush_thread = True
            self._flush_thread.start()

    def _open_connection(self):

        self.conn = None

        if 'http' == self.protocol.lower():
            self.conn = httplib.HTTPConnection(self.host, self.port)
        elif 'https' == self.protocol.lower():
            # never tested this - just copied what's in the Analytics ctor!
            self.conn = httplib.HTTPSConnection(self.host, self.port, self.key_file, self.cert_file)
        else:
            raise ChunkStreamerException("unknown protocol %s" % self.protocol)

        self.conn.putrequest("POST", "{0}".format(self.endpoint))
        self.conn.putheader("Host", "{0}:{1}".format(self.host, self.port))
        self.conn.putheader("Transfer-Encoding", "chunked")
        self.conn.putheader("Content-Type", "text/csv")
        self.conn.putheader("User-Agent", "AnalyticsPythonChunkStreamClient")
        #self.conn.putheader("Expect", "100-continue")
        self.conn.endheaders()
        self.opened = True

    def _periodic_flush_thread(self, period):

        # dances with close() in main thread:
        #   1 lock
        #   2 check shutdown flag - if set, break through to shutdown
        #   3 unlock (through finalizer)

        logger.info("Starting {0} flush thread with period {1}s".format(self, period))
        while True:
            logger.debug("{0} flush thread wakeup".format(self, period))
            with self.mutex:
                if self.opened:
                    if (time.time() - self.last_flush_time > period) and len(self.stream_buffer) > 0:
                        logger.info("{0} flush thread forcing flush".format(self))
                        self._flush()
                if self.run_flush_thread is False:
                    break
            # Don't sleep to long in relation to flush period
            time.sleep(min(1, period / 10.0))
        logger.info("Stopping {0} flush thread".format(self))

    def send(self, event, suffix='\r\n'):
        """
        Buffer and eventually emit event stream. If passed a non-string/dict, will attempt to
        JSON serialize from __dict__; this can be fragile, so use with caution (your class really
        ought to have it's own serialize method, which the application would use to produce a
        string to be passed here).
        """
        if isinstance(event, basestring):
            event_string = event
        elif isinstance(event, dict):
            event_string = json.dumps(event)
        else:
            event_string = json.dumps(event.__dict__)

        if self.closed:
            raise ChunkStreamerException("Streamer already closed; make a new one!")

        data = "".join([event_string + suffix])

        #if we ever support unbuffered send, this would be it:
        #self.conn.send(self.chunk_encode(data))

        first_event = False
        with self.mutex:
            if len(self.stream_buffer) == 0:
                first_event = True
            self.stream_buffer += str(data)
            if len(self.stream_buffer) >= self.buf_flush_threshold:
                retries_left = self.retries
                while True:
                    try:
                        self._flush()
                        break
                    except Exception, e:
                        time.sleep(0.5)
                        if retries_left > 0:
                            retries_left -= 1
                            logging.exception("problem flushing remaking connection retries: {0} out of {1}".format(retries_left, self.retries))
                            self.opened = False
                            self._open_connection()
                            continue
                        else:
                            raise ChunkStreamerException("Failed to send, even after {0} retries. Can't think of any helpful suggestions.".format(self.retries))

        return first_event

    def flush(self, check_reply=False):
        """
        End chunk up and flush buffer (if it's non-empty). Checking for replies is usually not
        needed; only do so if you're concerned that the event stream was somehow broken (e.g. if
        you were sending in opaque objects as events and there is a chance a required field was
        missing, then at some point jbird would have bitched about it and the stream would have
        broken -- idempotence would be a very good thing if that were a possibility). Flushing
        often is good (unless a flush thread was created, in which case it's implicit), but reply
        checking often is bad performance-wise.
        """
        if self.closed:
            raise ChunkStreamerException("Streamer already closed; make a new one!")
        with self.mutex:
            logger.debug("Flush on {0}, currently {1} chars in buffer".format(self, len(self.stream_buffer)))
            if len(self.stream_buffer) > 0:
                self._flush()
        if check_reply:
            retries_left = self.retries
            while True:
                self.conn.send(self.chunk_encode(None, end_chunk=True))
                if self._check_reply():
                    if retries_left > 0:
                        retries_left -= 1
                        time.sleep(0.5)
                        continue
                    else:
                        raise ChunkStreamerException("Failed to close off chunk and stream, even after {0} retries. Can't think of any helpful suggestions.".format(self.retries))
                else:
                    break
            self.opened = False
            self.conn.close()
            self._open_connection()

    def _flush(self):
        """ Chunk up and flush buffer. Requires mutex to be acquired. """
        if self.closed:
            raise ChunkStreamerException("Streamer already closed; make a new one!")
        assert self.mutex.locked(), "Should never reach here without the lock!"
        self.conn.send(self.chunk_encode(self.stream_buffer))
        self.stream_buffer = ''
        self.last_flush_time = time.time()

    def chunk_encode(self, string, end_chunk=False):
        """
        Experimentally-derived chunk encoding function; seems to work with jbird. Use with caution.
        """
        if end_chunk:
            return '0\r\n\r\n'
        else:
            #return '{0}\r\n{1}\r\n\r\n'.format(hex(len(str(string)))[2:], str(string))
            return ''.join([hex(len(string))[2:], '\r\n', string, '\r\n\r\n'])

    def _check_reply(self):
        """ Returns True if the previous request(s) should be retried. """
        try:
            resp = self.conn.getresponse()
        except httplib.BadStatusLine, e:
            logger.warn("{0}:{1} - {2} / remaking connection and then retrying".format(type(e), e, e.line))
            self._open_connection()
            return True

        replybody = resp.read()
        if int(resp.status / 100) != 2:
            raise ChunkStreamerException("HTTP Error (%d) on %s: %s" % (resp.status, self.endpoint, replybody))
        logger.debug("\n\nGet reply from {4} http stream:...\nerrcode: {0}\nerrmsg: {1}\nheaders: {2}\nreplybody: {3}".format(resp.status, resp.reason, resp.getheaders(), replybody, self))
        return False

    def _stop_flush_thread(self):
        if self.run_flush_thread:
            with self.mutex:
                self.run_flush_thread = False
            self._flush_thread.join()

    def abort(self):
        self._stop_flush_thread()
        self.conn.close()
        self.closed = True

    def close(self):
        """ Flush buffer, end chunk, and tear down HTTP connection (and flush thread). """

        if self.closed:
            raise ChunkStreamerException("Streamer already closed; make a new one!")

        # dances with flush thread shutdown:
        #   1 lock
        #   2 flag shutdown
        #   3 unlock
        #   4 wait for shutdown

        logger.info("Closing {0}{1}".format(self, ", need to stop flush thread" if self.run_flush_thread else ""))

        if self.run_flush_thread:
            self._stop_flush_thread()

        retries_left = self.retries
        while True:
            if len(self.stream_buffer) > 0:
                self.flush()
            self.conn.send(self.chunk_encode(None, end_chunk=True))
            if self._check_reply():
                if retries_left > 0:
                    retries_left -= 1
                    time.sleep(0.5)
                    continue
                else:
                    raise ChunkStreamerException("Failed to close off chunk and stream, even after {0} retries. Can't think of any helpful suggestions.".format(self.retries))
            else:
                break

        # close down http connection
        self.conn.close()
        self.closed = True

    def __str__(self):

        return '<{0} at: {1}, {2}:{3}:{4}{5}, cur buf len: {6}, ready: {7}>'.format(
            self.__class__,
            hex(id(self)),
            self.protocol,
            self.host,
            self.port,
            self.endpoint,
            len(self.stream_buffer),
            self.opened and not self.closed)

    def __repr__(self):

        # Care here with the magic __dict__ can easily hit
        # infinite recursion with loop of referenceS
        return "<{0} at {1}, ({2})>".format(self.__class__, hex(id(self)), self.__dict__)

    def __del__(self):
        if not self.closed:
            try:
                self.close()
            except Exception:
                logger.exception("Failed to properly clean up {0!r} due to".format(self))
