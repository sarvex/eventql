#!/usr/bin/env python

#tooltool is a lookaside cache implemented in Python
#Copyright (C) 2011 John H. Ford <john@johnford.info>
#
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation version 2
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# An manifest file specifies files in that directory that are stored
# elsewhere.  This file should only contain file in the directory
# which the manifest file resides in and it should be called 'manifest.manifest'

__version__ = '1'

import json
import os
import optparse
import logging
import hashlib
import urllib2
import ConfigParser

log = logging.getLogger(__name__)

class FileRecordJSONEncoderException(Exception): pass
class InvalidManifest(Exception): pass
class ExceptionWithFilename(Exception):
    def __init__(self, filename):
        Exception.__init__(self)
        self.filename = filename

class DigestMismatchException(ExceptionWithFilename): pass
class MissingFileException(ExceptionWithFilename): pass

class FileRecord(object):
    def __init__(self, filename, size, digest, algorithm):
        object.__init__(self)
        self.filename = filename
        self.size = size
        self.digest = digest
        self.algorithm = algorithm
        log.debug("creating %s 0x%x" % (self.__class__.__name__, id(self)))

    def __eq__(self, other):
        if self is other:
            return True
        return (
            self.filename == other.filename
            and self.size == other.size
            and self.digest == other.digest
            and self.algorithm == other.algorithm
        )

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"{__name__}.{self.__class__.__name__}(filename='{self.filename}', size='{self.size}', digest='{self.digest}', algorithm='{self.algorithm}')"

    def present(self):
        # Doesn't check validity
        return os.path.exists(self.filename)

    def validate_size(self):
        if self.present():
            return self.size == os.path.getsize(self.filename)
        log.debug("trying to validate size on a missing file, %s", self.filename)
        raise MissingFileException(filename=self.filename)

    def validate_digest(self):
        if self.present():
            with open(self.filename, 'rb') as f:
                return self.digest == digest_file(f, self.algorithm)
        else:
            log.debug("trying to validate digest on a missing file, %s', self.filename")
            raise MissingFileException(filename=self.filename)

    def validate(self):
        return bool(self.validate_size() and self.validate_digest())

    def describe(self):
        if self.present() and self.validate():
            return f"'{self.filename}' is present and valid"
        elif self.present():
            return f"'{self.filename}' is present and invalid"
        else:
            return f"'{self.filename}' is absent"


def create_file_record(filename, algorithm):
    with open(filename, 'rb') as fo:
        stored_filename = os.path.split(filename)[1]
        fr = FileRecord(stored_filename, os.path.getsize(filename), digest_file(fo, algorithm), algorithm)
    return fr


class FileRecordJSONEncoder(json.JSONEncoder):
    def encode_file_record(self, obj):
        if issubclass(type(obj), FileRecord):
            return {'filename': obj.filename, 'size': obj.size, 'algorithm': obj.algorithm, 'digest': obj.digest}
        err = f"FileRecordJSONEncoder is only for FileRecord and lists of FileRecords, not {obj.__class__.__name__}"
        log.warn(err)
        raise FileRecordJSONEncoderException(err)

    def default(self, f):
        if issubclass(type(f), list):
            return [self.encode_file_record(i) for i in f]
        else:
            return self.encode_file_record(f)


class FileRecordJSONDecoder(json.JSONDecoder):
    """I help the json module materialize a FileRecord from
    a JSON file.  I understand FileRecords and lists of
    FileRecords.  I ignore things that I don't expect for now"""
    # TODO: make this more explicit in what it's looking for
    # and error out on unexpected things
    def process_file_records(self, obj):
        if isinstance(obj, list):
            record_list = []
            for i in obj:
                record = self.process_file_records(i)
                if issubclass(type(record), FileRecord):
                    record_list.append(record)
            return record_list
        if isinstance(obj, dict) and \
               len(obj.keys()) == 4 and \
               obj.has_key('filename') and \
               obj.has_key('size') and \
               obj.has_key('algorithm') and \
               obj.has_key('digest'):
            rv = FileRecord(obj['filename'], obj['size'], obj['digest'], obj['algorithm'])
            log.debug(f"materialized {rv}")
            return rv
        return obj

    def decode(self, s):
        decoded = json.JSONDecoder.decode(self, s)
        return self.process_file_records(decoded)


class Manifest(object):

    valid_formats = ('json',)

    def __init__(self, file_records=[]):
        self.file_records = file_records

    def __eq__(self, other):
        if self is other:
            return True
        if len(self.file_records) != len(other.file_records):
            log.debug('Manifests differ in number of files')
            return False
        #TODO: Lists in a different order should be equal
        for record in range(0,len(self.file_records)):
            if self.file_records[record] != other.file_records[record]:
                log.debug(
                    f'FileRecords differ, {self.file_records[record]} vs {other.file_records[record]}'
                )
                return False
        return True

    def __deepcopy__(self, memo):
        # This is required for a deep copy
        return Manifest(self.file_records[:])

    def __copy__(self):
        return Manifest(self.file_records)

    def copy(self):
        return Manifest(self.file_records[:])

    def present(self):
        return all(i.present() for i in self.file_records)

    def validate_sizes(self):
        return all(i.validate_size() for i in self.file_records)

    def validate_digests(self):
        return all(i.validate_digest() for i in self.file_records)

    def validate(self):
        return all(i.validate() for i in self.file_records)

    def sort(self):
        #TODO: WRITE TESTS
        self.file_records.sort(key=lambda x: x.size)

    def load(self, data_file, fmt='json'):
        assert fmt in self.valid_formats
        if fmt == 'json':
            try:
                self.file_records.extend(json.load(data_file, cls=FileRecordJSONDecoder))
                self.sort()
            except ValueError:
                raise InvalidManifest("trying to read invalid manifest file")

    def loads(self, data_string, fmt='json'):
        assert fmt in self.valid_formats
        if fmt == 'json':
            try:
                self.file_records.extend(json.loads(data_string, cls=FileRecordJSONDecoder))
                self.sort()
            except ValueError:
                raise InvalidManifest("trying to read invalid manifest file")

    def dump(self, output_file, fmt='json'):
        assert fmt in self.valid_formats
        self.sort()
        if fmt == 'json':
            rv = json.dump(self.file_records, output_file, indent=0, cls=FileRecordJSONEncoder)
            print >> output_file, ''
            return rv

    def dumps(self, fmt='json'):
        assert fmt in self.valid_formats
        self.sort()
        if fmt == 'json':
            return json.dumps(self.file_records, cls=FileRecordJSONEncoder)


def digest_file(f, a):
    """I take a file like object 'f' and return a hex-string containing
    of the result of the algorithm 'a' applied to 'f'."""
    h = hashlib.new(a)
    chunk_size = 1024*10
    while data := f.read(chunk_size):
        h.update(data)
    if hasattr(f, 'name'):
        log.debug('hashed %s with %s to be %s', f.name, a, h.hexdigest())
    else:
        log.debug('hashed a file with %s to be %s', a, h.hexdigest())
    return h.hexdigest()

# TODO: write tests for this function
def open_manifest(manifest_file):
    """I know how to take a filename and load it into a Manifest object"""
    if os.path.exists(manifest_file):
        manifest = Manifest()
        with open(manifest_file) as f:
            manifest.load(f)
            log.debug(f"loaded manifest from file '{manifest_file}'")
        return manifest
    else:
        log.debug(f"tried to load absent file '{manifest_file}' as manifest")
        raise InvalidManifest(f"manifest file '{manifest_file}' does not exist")

# TODO: write tests for this function
def list_manifest(manifest_file):
    """I know how print all the files in a location"""
    try:
        manifest = open_manifest(manifest_file)
    except InvalidManifest:
        log.error("failed to load manifest file at '%s'" % manifest_file)
        return False
    for f in manifest.file_records:
        print "%s\t%s\t%s" % ("P" if f.present() else "-",
                              "V" if f.present() and f.validate() else "-",
                              f.filename)
    return True

def validate_manifest(manifest_file):
    """I validate that all files in a manifest are present and valid but
    don't fetch or delete them if they aren't"""
    try:
        manifest = open_manifest(manifest_file)
    except InvalidManifest:
        log.error(f"failed to load manifest file at '{manifest_file}'")
        return False
    invalid_files = []
    absent_files = []
    for f in manifest.file_records:
        if not f.present():
            absent_files.append(f)
        elif not f.validate():
            invalid_files.append(f)
    return len(invalid_files + absent_files) == 0

# TODO: write tests for this function
def add_files(manifest_file, algorithm, filenames):
    # returns True if all files successfully added, False if not
    # and doesn't catch library Exceptions.  If any files are already
    # tracked in the manifest, return will be False because they weren't
    # added
    all_files_added = True
    # Create a old_manifest object to add to
    if os.path.exists(manifest_file):
        old_manifest = open_manifest(manifest_file)
    else:
        old_manifest = Manifest()
        log.debug("creating a new manifest file")
    new_manifest = Manifest() # use a different manifest for the output
    for filename in filenames:
        log.debug(f"adding {filename}")
        path, name = os.path.split(filename)
        new_fr = create_file_record(filename, algorithm)
        log.debug("appending a new file record to manifest file")
        add = True
        for fr in old_manifest.file_records:
            log.debug(
                f"""manifest file has '{"', ".join([x.filename for x in old_manifest.file_records])}'"""
            )
            if new_fr == fr and new_fr.validate():
                # TODO: Decide if this case should really cause a False return
                log.info("file already in old_manifest file and matches")
                add = False
            elif new_fr == fr and not new_fr.validate():
                log.error("file already in old_manifest file but is invalid")
                add = False
            if filename == fr.filename:
                log.error(f"manifest already contains file named {filename}")
                add = False
        if add:
            new_manifest.file_records.append(new_fr)
            log.debug(f"added '{filename}' to manifest")
        else:
            all_files_added = False
    with open(manifest_file, 'wb') as output:
        new_manifest.dump(output, fmt='json')
    return all_files_added


# TODO: write tests for this function
def fetch_file(base_url, file_record, overwrite=False, grabchunk=1024*4):
    # A file which is requested to be fetched that exists locally will be hashed.
    # If the hash matches the requested file's hash, nothing will be done and the
    # function will return.  If the function is told to overwrite and there is a 
    # digest mismatch, the exiting file will be overwritten
    if file_record.present():
        if file_record.validate():
            log.info(f"existing '{file_record.filename}' is valid, not fetching")
            return True
        if overwrite:
            log.info(f"overwriting '{file_record.filename}' as requested")
        else:
            # All of the following is for a useful error message
            with open(file_record.filename, 'rb') as f:
                d = digest_file(f, file_record.algorithm)
            log.error(
                f"digest mismatch between manifest({file_record.digest[:8]}...) and local file({d[:8]}...)"
            )
            log.debug(f"full digests: manifest ({file_record.digest}) local file ({d})")
            # Let's bail!
            return False

    # Generate the URL for the file on the server side
    url = f"{base_url}/{file_record.algorithm}/{file_record.digest}"

    log.debug(f"fetching from '{url}'")

    # TODO: This should be abstracted to make generic retreival protocol handling easy
    # Well, the file doesn't exist locally.  Lets fetch it.
    try:
        f = urllib2.urlopen(url)
        log.debug(f"opened {url} for reading")
        with open(file_record.filename, 'wb') as out:
            k = True
            size = 0
            while k:
                # TODO: print statistics as file transfers happen both for info and to stop
                # buildbot timeouts
                indata = f.read(grabchunk)
                out.write(indata)
                size += len(indata)
                if indata == '':
                    k = False
            if size != file_record.size:
                log.error("transfer from %s to %s failed due to a difference of %d bytes" % (url,
                            file_record.filename, file_record.size - size))
                return False
            log.info(f"fetched {file_record.filename}")
    except (urllib2.URLError, urllib2.HTTPError) as e:
        log.error(f"failed to fetch '{file_record.filename}': {e}", exc_info=True)
        return False
    except IOError:
        log.error(f"failed to write to '{file_record.filename}'", exc_info=True)
        return False
    return True


# TODO: write tests for this function
def fetch_files(manifest_file, base_url, overwrite, filenames=[]):
    # Lets load the manifest file
    try:
        manifest = open_manifest(manifest_file)
    except InvalidManifest:
        log.error(f"failed to load manifest file at '{manifest_file}'")
        return False
    # We want to track files that fail to be fetched as well as
    # files that are fetched
    failed_files = []

    # Lets go through the manifest and fetch the files that we want
    fetched_files = []
    for f in manifest.file_records:
        if f.filename in filenames or len(filenames) == 0:
            log.debug(f"fetching {f.filename}")
            if fetch_file(base_url, f, overwrite):
                fetched_files.append(f)
            else:
                failed_files.append(f.filename)
        else:
            log.debug(f"skipping {f.filename}")

    # Even if we get the file, lets ensure that it matches what the
    # manifest specified
    for localfile in fetched_files:
        if not localfile.validate():
            log.error(f"'{localfile.describe()}'")

    # If we failed to fetch or validate a file, we need to fail
    if failed_files:
        log.error(f"""The following files failed: '{"', ".join(failed_files)}'""")
        return False
    return True


# TODO: write tests for this function
def process_command(options, args):
    """ I know how to take a list of program arguments and
    start doing the right thing with them"""
    cmd = args[0]
    cmd_args = args[1:]
    log.debug(
        f"""processing '{cmd}' command with args '{'", "'.join(cmd_args)}'"""
    )
    log.debug(f"using options: {options}")
    if cmd == 'list':
        return list_manifest(options['manifest'])
    if cmd == 'validate':
        return validate_manifest(options['manifest'])
    elif cmd == 'add':
        return add_files(options['manifest'], options['algorithm'], cmd_args)
    elif cmd == 'fetch':
        if not options.has_key('base_url') or options.get('base_url') is None:
            log.critical('fetch command requires url option')
            return False
        return fetch_files(options['manifest'], options['base_url'], options['overwrite'], cmd_args)
    else:
        log.critical(f'command "{cmd}" is not implemented')
        return False

# fetching api:
#   http://hostname/algorithm/hash
#   example: http://people.mozilla.org/sha1/1234567890abcedf
# This will make it possible to have the server allow clients to
# use different algorithms than what was uploaded to the server

# TODO: Implement the following features:
#   -optimization: do small files first, justification is that they are faster
#    and cause a faster failure if they are invalid
#   -store permissions
#   -local renames i.e. call the file one thing on the server and
#    something different locally
#   -deal with the cases:
#     -local data matches file requested with different filename
#     -two different files with same name, different hash
#   -?only ever locally to digest as filename, symlink to real name
#   -?maybe deal with files as a dir of the filename with all files in that dir as the versions of that file
#      - e.g. ./python-2.6.7.dmg/0123456789abcdef and ./python-2.6.7.dmg/abcdef0123456789

def main():
    # Set up logging, for now just to the console
    ch = logging.StreamHandler()
    cf = logging.Formatter("%(levelname)s - %(message)s")
    ch.setFormatter(cf)

    # Set up option parsing
    parser = optparse.OptionParser()
    # I wish there was a way to say "only allow args to be
    # sequential and at the end of the argv.
    # OH! i could step through sys.argv and check for things starting without -/-- before things starting with them
    parser.add_option('-q', '--quiet', default=False,
            dest='quiet', action='store_true')
    parser.add_option('-v', '--verbose', default=False,
            dest='verbose', action='store_true')
    parser.add_option('-m', '--manifest', default='manifest.tt',
            dest='manifest', action='store',
            help='specify the manifest file to be operated on')
    parser.add_option('-d', '--algorithm', default='sha512',
            dest='algorithm', action='store',
            help='openssl hashing algorithm to use')
    parser.add_option('-o', '--overwrite', default=False,
            dest='overwrite', action='store_true',
            help='if fetching, remote copy will overwrite a local copy that is different. ')
    parser.add_option('--url', dest='base_url', action='store',
            help='base url for fetching files')
    parser.add_option('--ignore-config-files', action='store_true', default=False,
                     dest='ignore_cfg_files')
    (options_obj, args) = parser.parse_args()
    # Dictionaries are easier to work with
    options = vars(options_obj)


    # Use some of the option parser to figure out application
    # log level
    if options.get('verbose'):
        ch.setLevel(logging.DEBUG)
    elif options.get('quiet'):
        ch.setLevel(logging.ERROR)
    else:
        ch.setLevel(logging.INFO)
    log.addHandler(ch)

    cfg_file = ConfigParser.SafeConfigParser()
    if not options.get("ignore_cfg_files"):
        read_files = cfg_file.read(['/etc/tooltool', os.path.expanduser('~/.tooltool'),
                   os.path.join(os.getcwd(), '.tooltool')])
        log.debug(f"""read in the config files '{'", '.join(read_files)}'""")
    else:
        log.debug("skipping config files")

    for option in ('base_url', 'algorithm'):
        if not options.get(option):
            try:
                options[option] = cfg_file.get('general', option)
                log.debug(f"read '{option}' as '{options[option]}' from cfg_file")
            except (ConfigParser.NoSectionError, ConfigParser.NoOptionError) as e:
                log.debug(f"{e} in config file", exc_info=True)

    if not options.has_key('manifest'):
        parser.error("no manifest file specified")

    if len(args) < 1:
        parser.error('You must specify a command')
    exit(0 if process_command(options, args) else 1)

if __name__ == "__main__":
    main()
else:
    log.addHandler(logging.NullHandler())
    #log.addHandler(logging.StreamHandler())
