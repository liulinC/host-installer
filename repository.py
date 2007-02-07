# Copyright (c) 2005-2006 XenSource, Inc. All use and distribution of this 
# copyrighted material is governed by and subject to terms and conditions 
# as licensed by XenSource, Inc. All other rights reserved.
# Xen, XenSource and XenEnterprise are either registered trademarks or 
# trademarks of XenSource Inc. in the United States and/or other countries.

###
# XEN CLEAN INSTALLER
# Packaging functions
#
# written by Andrew Peace

import xelogging
import diskutil

import os
import md5
import tempfile
import urllib2
import util
import popen2

class NoRepository(Exception):
    pass

class UnknownPackageType(Exception):
    pass

class ErrorInstallingPackage(Exception):
    pass

class Repository:
    """ Represents a XenSource repository containing packages and associated
    meta data. """
    REPOSITORY_FILENAME = "XS-REPOSITORY"
    PKGDATA_FILENAME = "XS-PACKAGES"

    def __init__(self, accessor, base = ""):
        self._accessor = accessor
        self._base = base

        accessor.start()

        try:
            repofile = accessor.openAddress(self.path(self.REPOSITORY_FILENAME))
        except Exception, e:
            raise NoRepository, e
        self._parse_repofile(repofile)
        repofile.close()

        try:
            pkgfile = accessor.openAddress(self.path(self.PKGDATA_FILENAME))
        except Exception, e:
            raise NoRepository, e
        self._parse_packages(pkgfile)
        repofile.close()

        accessor.finish()

    def isRepo(cls, accessor, base):
        """ Return whether there is a repository at base address 'base' accessible
        using accessor."""
        return False not in [ accessor.access(accessor.pathjoin(base, f)) for f in [cls.REPOSITORY_FILENAME, cls.PKGDATA_FILENAME] ]
    isRepo = classmethod(isRepo)

    def _parse_repofile(self, repofile):
        """ Parse repository data -- get repository identifier and name. """
        lines = repofile.readlines()
        self._identifier = lines[0].strip()
        self._name = lines[1].strip()

    def name(self):
        return self._name

    def identifier(self):
        return self._identifier

    def path(self, name):
        return self._accessor.pathjoin(self._base, name)

    def _parse_packages(self, pkgfile):
        pkgtype_mapping = {
            'tbz2' : BzippedPackage
            }
        
        lines = pkgfile.readlines()
        self._packages = []
        for line in lines:
            pkgdata_raw = line.strip().split(" ")
            (_name, _size, _md5sum, _type) = pkgdata_raw[:4]
            if pkgtype_mapping.has_key(_type):
                pkg = pkgtype_mapping[_type](self, _name, _size, _md5sum, *pkgdata_raw[4:])
                pkg.type = _type
            else:
                raise UnknownPackageType, _type

            self._packages.append(pkg)

    def check(self, progress = lambda x: ()):
        """ Return a list of problematic packages. """
        def pkg_progress(start, end):
            def progress_fn(x):
                progress(start + ((x * (end - start)) / 100))
            return progress_fn

        self._accessor.start()

        try:
            problems = []
            total_size = reduce(lambda x,y: x + y,
                                [ p.size for p in self._packages ])
            total_progress = 0
            for p in self._packages:
                start = (total_progress * 100) / total_size
                end = ((total_progress + p.size) * 100) / total_size
                if not p.check(False, pkg_progress(start, end)):
                    problems.append(p)
                total_progress += p.size
        finally:
            self._accessor.finish()
        return problems

    def accessor(self):
        return self._accessor

    def __iter__(self):
        return self._packages.__iter__()

class BzippedPackage:
    def __init__(self, repository, name, size, md5sum, required, src, dest):
        (
            self.repository,
            self.name,
            self.size,
            self.md5sum,
            self.required,
            self.repository_filename,
            self.destination
        ) = ( repository, name, long(size), md5sum, required == 'required', src, dest )

        self.destination = self.destination.lstrip('/')

    def install(self, base, progress = lambda x: ()):
        """ Install package to base.  Progress function takes values from 0
        to 100. """
        pkgpath = self.repository.path(self.repository_filename)
        package = self.repository.accessor().openAddress(pkgpath)

        xelogging.log("Starting installation of package %s" % self.name)
        
        pipe = popen2.Popen3('tar -C %s -xjf - &>/dev/null' % os.path.join(base, self.destination), bufsize = 1024 * 1024)
    
        data = ''
        current_progress = 0
        while True:
            # read in 10mb chunks so as not to use so much RAM, and to
            # allow decompression to occur in parallel (in the bzip2
            # process).
            data = package.read(10485760)
            if data == '':
                break
            else:
                pipe.tochild.write(data)
            current_progress += len(data)
            progress(current_progress / 100)

        pipe.tochild.flush()
    
        pipe.tochild.close()
        pipe.fromchild.close()
        rc = pipe.wait()
        if rc != 0:
            raise ErrorInstallingPackage, "The decompressor returned with a non-zero exit code (rc %d) whilst processing package %s" % (rc, self.name)
    
        package.close()

    def check(self, fast = False, progress = lambda x: ()):
        """ Check a package against it's known checksum, or if fast is
        specified, just check that the package exists. """
        path = self.repository.path(self.repository_filename)
        if fast:
            return self.repository.accessor().access(path)
        else:
            try:
                pkgfd = self.repository.accessor().openAddress(path)

                xelogging.log("Validating package %s" % self.name)
                m = md5.new()
                data = ''
                total_read = 0
                while True:
                    data = pkgfd.read(10485760)
                    total_read += len(data)
                    if data == '':
                        break
                    else:
                        m.update(data)
                    progress(total_read / (self.size / 100))
                
                pkgfd.close()
                
                calculated = m.hexdigest()
                valid = (self.md5sum == calculated)
                xelogging.log("Result: %s " % str(valid))
                return valid
            except Exception, e:
                return False

    def __repr__(self):
        return "<BzippedPackage: %s>" % self.name

class Accessor:
    def pathjoin(base, name):
        return os.path.join(base, name)
    pathjoin = staticmethod(pathjoin)

    def access(self, name):
        """ Return boolean determining where 'name' is an accessible object
        in the target. """
        try:
            f = self.openAddress(name)
            f.close()
        except:
            return False
        else:
            return True

    def start(self):
        pass

    def finish(self):
        pass
    
    def findRepositories(self):
        # Check known locations:
        repos = []
        for loc in ['', 'packages', 'packages.main', 'packages.linux']:
            if Repository.isRepo(self, loc):
                repos.append(Repository(self, loc))
        return repos

class MountingAccessor(Accessor):
    def __init__(self, mount_type, mount_source, mount_options = ['ro']):
        (
            self.mount_type,
            self.mount_source,
            self.mount_options
        ) = (mount_type, mount_source, mount_options)
        self.mountpoint = None
        self.start_count = 0

    def start(self):
        if self.start_count == 0:
            self.mountpoint = tempfile.mkdtemp(prefix="media-", dir="/tmp")
            util.mount(self.mount_source, self.mountpoint,
                       options = self.mount_options,
                       fstype = self.mount_type)
        self.start_count += 1

    def finish(self):
        if self.start_count == 0:
            return
        self.start_count = self.start_count - 1
        if self.start_count == 0:
            util.umount(self.mountpoint)
            os.rmdir(self.mountpoint)
            self.mountpoint = None

    def openAddress(self, addr):
        return open(os.path.join(self.mountpoint, addr), 'r')

    def __del__(self):
        while self.mountpoint:
            self.finish()

class DeviceAccessor(MountingAccessor):
    def __init__(self, device, fs='iso9660'):
        """ Return a MountingAccessor for a device 'device', which should
        be a fully qualified path to a device node. """
        MountingAccessor.__init__(self, fs, device)
        self.device = device

class NFSAccessor(MountingAccessor):
    def __init__(self, nfspath):
        MountingAccessor.__init__(self, 'nfs', nfspath)

class URLAccessor(Accessor):
    url_prefixes = ['http://', 'https://', 'ftp://']

    def __init__(self, baseAddress):
        if not True in [ baseAddress.startswith(prefix) for prefix in self.url_prefixes ] :
            xelogging.log("Base address: no known protocol specified, prefixing http://")
            baseAddress = "http://" + baseAddress
        if not baseAddress.endswith('/'):
            xelogging.log("Base address: did not end with '/' but should be a directory so adding it.")
            baseAddress += '/'

        xelogging.log("Initialising URLRepositoryAccessor with base address %s" % baseAddress)
        self.baseAddress = baseAddress

    def _url_concat(url1, end):
        assert url1.endswith('/')
        end = end.lstrip('/')
        return url1 + end
    _url_concat = staticmethod(_url_concat)

    def start(self):
        pass

    def finish(self):
        pass

    def openAddress(self, address):
        return urllib2.urlopen(self._url_concat(self.baseAddress, address))

def repositoriesFromDefinition(media, address):
    if media == 'local':
        # this is a special case as we need to locate the media first
        return findRepositoriesOnMedia()
    else:
        if media == 'url':
            accessor = URLAccessor(address)
        elif media == 'nfs':
            accessor = NFSAccessor(address)
        else:
            raise RuntimeError, "Unknown repository media %s" % media

        accessor.start()
        rv = accessor.findRepositories()
        accessor.finish()
        return rv

def findRepositoriesOnMedia():
    """ Given a repository ID, searches for that repository
    on removable media and returns a repository object. """

    static_devices = [
    'hda', 'hdb', 'hdc', 'hdd', 'hde', 'hdf',
    'sda', 'sdb', 'sdc', 'sdd', 'sde', 'sdf',
    'scd0', 'scd1', 'scd2', 'scd3', 'scd4',
    'sr0', 'sr1', 'sr2', 'sr3', 'sr4', 'sr5', 'sr6', 'sr7',
    'cciss/c0d0', 'cciss/c0d1'
    ]

    removable_devices = diskutil.getRemovableDeviceList()
    removable_devices = filter(lambda x: not x.startswith('fd'),
                               removable_devices)

    da = None
    repos = []
    try:
        for check in removable_devices + static_devices:
            device_path = "/dev/%s" % check
            xelogging.log("Looking for repositories: %s" % device_path)
            if os.path.exists(device_path):
                da = DeviceAccessor(device_path)
                try:
                    da.start()
                except util.MountFailureException:
                    da = None
                    continue
                repos = da.findRepositories()
                if repos:
                    return repos
    finally:
        if da:
            da.finish()

    return []