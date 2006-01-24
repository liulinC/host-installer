###
# XEN CLEAN INSTALLER
# Functions to perform the XE installation
#
# written by Mark Nijmeijer
# Copyright XenSource Inc. 2006

import os
import os.path

import p2v_tui
import p2v_uicontroller
import findroot
import sys
import constants
import p2v_utils

def print_results( results ):
    if p2v_utils.is_debug():
        for key in results.keys():
            sys.stderr.write( "result.key = %s \t\t" % key )
            sys.stderr.write( "result.value = %s\n" % results[key] )
         
def mount_os_root( os_root_device, dev_attrs ):
    return findroot.mount_os_root( os_root_device, dev_attrs )
 
def umount_os_root( mnt ):
    return findroot.umount_dev( mnt )

def append_hostname(os_install): 
    os_install[constants.HOST_NAME] = os.uname()[1]

def determine_size(os_install):
    os_root_device = os_install[constants.DEV_NAME]
    dev_attrs = os_install[constants.DEV_ATTRS]
    os_root_mount_point = mount_os_root( os_root_device, dev_attrs )
    size = findroot.determine_size(os_root_mount_point, os_root_device )
    os_install[constants.FS_USED_SIZE] = size
    umount_os_root( os_root_mount_point )
    

def perform_p2v( os_install, inbox_path ):
    os_root_device = os_install[constants.DEV_NAME]
    dev_attrs = os_install[constants.DEV_ATTRS]
    os_root_mount_point = mount_os_root( os_root_device, dev_attrs )
    rc, tarfilename, md5sum = findroot.handle_root( os_root_mount_point, os_root_device )
    os_install[constants.XEN_TAR_FILENAME] = tarfilename
    os_install[constants.XEN_TAR_MD5SUM] = md5sum
    umount_os_root( os_root_mount_point )
    
def nfs_mount( nfs_mount_path ):
    local_mount_path = "/xenpending"
    findroot.run_command( "mkdir -p /xenpending" )
    findroot.run_command( "mount %s %s %s" % ( nfs_mount_path, local_mount_path, p2v_utils.show_debug_output() ) )
    return local_mount_path

#TODO : validation of nfs_path?         
def nfs_p2v( nfs_host, nfs_path, os_install ):
    nfs_mount_path = nfs_host + ":" + nfs_path
    inbox_path = nfs_mount( nfs_mount_path )
    perform_p2v( os_install, inbox_path )
        
def mount_inbox( xe_host ):    
    inbox_path = "/inbox"
    fs_mount_path = nfs_mount( xe_host +":" + inbox_path )
    return fs_mount_path

def xe_p2v( xe_host, os_install ):
    inbox_path = mount_inbox( xe_host )
    perform_p2v( os_install, inbox_path )
         
def perform_P2V( results ):
    os_install = results[constants.OS_INSTALL]
    determine_size(os_install)
    append_hostname(os_install)
    if results[constants.XEN_TARGET] == constants.XEN_TARGET_XE:
        p2v_utils.trace_message( "we're doing a p2v to XE" )
        xe_host = results[constants.XE_HOST]
        xe_p2v( xe_host, os_install )
    elif results[constants.XEN_TARGET] == constants.XEN_TARGET_NFS:
        p2v_utils.trace_message( "we're doing a p2v to XE" )
        nfs_host = results[constants.NFS_HOST]
        nfs_path = results[constants.NFS_PATH]
        nfs_p2v( nfs_host, nfs_path, os_install )
    write_template(os_install)
    return 0
    
def open_tag(tag, value = ""):
    template_string = ""
    template_string += "("
    template_string += tag
    template_string += " "
    template_string += value
    return template_string
    
def close_tag(tag):
    template_string = ""
    template_string += ") "
    return template_string
    #tag is unused
    
#TODO: add implementation
def determine_distrib(os_install):
    os_name = os_install[constants.OS_NAME]
    if os_name == "Red Hat":
        return "rhel"
    elif os_name == "SuSE":
        return "sles"
    
def add_xgt_version():
    template_string = ""
    template_string += open_tag(constants.TAG_XGT_VERSION, "4")
    template_string += close_tag(constants.TAG_XGT_VERSION)
    return template_string

def add_xgt_type():
    template_string = ""
    template_string += open_tag(constants.TAG_XGT_TYPE, "archive")
    template_string += close_tag(constants.TAG_XGT_TYPE)
    return template_string
    
def add_name(os_install):
    template_string = ""
    host_name = os_install[constants.HOST_NAME]
    os_name = os_install[constants.OS_NAME]
    os_version = os_install[constants.OS_VERSION]
    template_string += open_tag(constants.TAG_NAME, "'P2V of os_install %s %s of host %s'" % (os_name, os_version, host_name))
    template_string += close_tag(constants.TAG_NAME)
    return template_string
    
def add_distrib(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_DISTRIB, determine_distrib(os_install))
    template_string += close_tag( constants.TAG_DISTRIB)
    return template_string

def add_uri(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_FILESYSTEM_URI, os_install[constants.XEN_TAR_FILENAME])
    template_string += close_tag( constants.TAG_FILESYSTEM_URI)
    return template_string

def add_function(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_FILESYSTEM_FUNCTION, 'root')
    template_string += close_tag( constants.TAG_FILESYSTEM_FUNCTION)
    return template_string

def add_type(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_FILESYSTEM_TYPE, 'tar')
    template_string += close_tag( constants.TAG_FILESYSTEM_TYPE)
    return template_string
    
def add_vbd(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_FILESYSTEM_VBD, os.path.basename(os_install[constants.DEV_NAME]))
    template_string += close_tag( constants.TAG_FILESYSTEM_VBD)
    return template_string

def add_md5sum(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_FILESYSTEM_MD5SUM,  os_install[constants.XEN_TAR_MD5SUM])
    template_string += close_tag( constants.TAG_FILESYSTEM_MD5SUM)
    return template_string

def add_total_size(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_FILESYSTEM_TOTAL_SIZE,  os_install[constants.FS_USED_SIZE])
    template_string += close_tag( constants.TAG_FILESYSTEM_TOTAL_SIZE)
    return template_string

def add_used_size(os_install):
    template_string = ""
    template_string += open_tag(constants.TAG_FILESYSTEM_USED_SIZE,  os_install[constants.FS_USED_SIZE])
    template_string += close_tag( constants.TAG_FILESYSTEM_USED_SIZE)
    return template_string

def add_filesystem(os_install):
    template_string = ""
    os_root_device = os_install[constants.DEV_NAME]
    dev_attrs = os_install[constants.DEV_ATTRS]
    fs_used_size = os_install[constants.FS_USED_SIZE]
    template_string += open_tag(constants.TAG_FILESYSTEM)
    template_string += add_uri(os_install)
    template_string += add_function(os_install)
    template_string += add_type(os_install)
    template_string += add_vbd(os_install)
    template_string += add_md5sum(os_install)
    template_string += add_total_size(os_install)
    template_string += add_used_size(os_install)
    template_string += close_tag(constants.TAG_FILESYSTEM)
    return template_string
         
def write_template(os_install):
    template_string = ""
    
    template_string += open_tag(constants.TAG_XGT)
    template_string += add_xgt_version()
    template_string += add_xgt_type()
    template_string += add_name(os_install)
    template_string += add_distrib(os_install)
    template_string += add_filesystem(os_install)
    template_string += close_tag(constants.TAG_XGT)
    
    p2v_utils.trace_message("template  = %s\n" % template_string)
    
    return
