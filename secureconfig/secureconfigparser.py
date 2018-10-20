

import sys

import cryptography

from .baseclass import cryptkeeper_access_methods
from configparser import ConfigParser, NoSectionError, NoOptionError


# SECURECONFIG pattern:
#  - allow key retrieval and storage from CryptKeeper object
#  - default to symmetric keys using AES (via Fernet)
#  - (future) provide asymmetric encryption using RSA 

# SECURECONFIGPARSER pattern:
#  - read list of files
#  - read and interpolate vars
#  - has .ck attribute -> CryptKeeper object
#
#

# GLOSSARY OF VARIABLE NAMES
#
# sec == section
# ck = CryptKeeper object

# ConfigParser is an "old style" class, so we're using old-style calls to super
# until ConfigParser gets its act together.

# oh god multiple inheritance 
# /me crosses her fingers

class SecureConfigParser(ConfigParser, cryptkeeper_access_methods):
    '''A subclass of ConfigParser py:class::ConfigParser which decrypts certain entries.'''

    def __init__(self, *args, **kwargs):
        
        # supplied by cryptkeeper_access_methods
        self.ck = kwargs.pop('ck', None) 
        
        ConfigParser.__init__(self, *args, **kwargs)
    
    def read(self, filenames):
        '''Read the list of config files.'''
        #print("[DEBUG] filenames: ", filenames)
        for fn in filenames:
            assert(type(fn) == str)

        ConfigParser.read(self, filenames)

    def raw_get(self, sec, key, default=None):
        '''Get the raw value without decoding it.'''
        assert(type(sec) == str)
        assert(type(key) == str)
        if default is not None:
            assert(type(default) == str)
        try:
            return ConfigParser.get(self, sec, key, raw=True)
            #return super(SecureConfigParser, self).get(sec, key)
        except (NoSectionError, NoOptionError):
            return default
        except Exception as e:
            print("[DEBUG]", sys.exc_info()[0])
            
    def raw_set(self, sec, key, val):
        '''Set the value without encrypting it.'''
        assert(type(sec) == str)
        assert(type(key) == str)
        assert(type(val) == str)
        out = ConfigParser.set(self, sec, key, val)
        if out is not None:
            assert(type(out) == str)
        return val

    def raw_items(self, sec):
        '''Return the items in a section without decrypting the values.'''
        for k, v in ConfigParser.items(self, sec, raw=False):
            assert(type(k) == str)
            assert(type(v) == str)
            yield k, v

    def val_decrypt(self, raw_val, **kwargs):
        '''Decrypt supplied value if it appears to be encrypted.'''
        assert(type(raw_val) == str)
        if self.ck and raw_val.startswith(self.ck.sigil):
            out = self.ck.crypter.decrypt(raw_val.split(self.ck.sigil)[1].encode())#.decode()
        else:
            out = raw_val
        return out

    def get(self, sec, key, default=None, fallback=None, raw=False):
        '''Get the value from the config, possibly decrypting it.'''
        assert(type(sec) == str)
        assert(type(key) == str)
        if default is not None:
            assert(type(default) == str)
        if fallback is not None:
            assert(type(fallback) == str)
        assert(type(raw) == bool)
        raw_val = self.raw_get(sec, key)
        if raw_val is None:
            if default is None:
                # https://github.com/cimichaelm/python3-secureconfig/issues/2
                return fallback
            else:
                return default
        val = self.val_decrypt(raw_val, sec=sec, key=key).decode()
        assert(type(val) == str)
        return val

    def set(self, sec, key, new_val, encrypt=False):
        '''If the value should be secured, encrypt and update it; 
            Otherwise just update it.  supply encrypt=True to encrypt
            a value that was not previously encrypted.
        '''
        assert(type(sec) == str)
        assert(type(key) == str)
        assert(type(new_val) == str)
        assert(type(encrypt) == bool)

        if not self.has_option(sec, key):
            if encrypt==True:
                #import pdb
                #pdb.set_trace()
                #new_val = self.ck.sigil + self.ck.encrypt(new_val).decode('ascii')
                new_val = self.ck.sigil + self.ck.encrypt(new_val.encode('utf8')).decode()
            out = self.raw_set(sec, key, new_val)
            assert(type(out) == str)
            return out
        
        old_raw_val = self.raw_get(sec, key)

        if old_raw_val.startswith(self.ck.sigil) or encrypt==True:
            new_val = self.ck.sigil + self.ck.encrypt(new_val).decode()
            out = self.raw_set(sec, key, new_val)
            assert(type(out) == str)
            return out

        out = self.raw_set(sec, key, new_val)
        assert(type(out) == str)
        return out

    def items(self, sec):
        '''Iterate over the items; decoding the values.'''
        assert(type(sec) == str)
        for (key, val) in self.raw_items(sec):
            assert(type(key) == str)
            assert(type(val) == str)
            val = self.val_decrypt(val, sec=sec, key=key).decode()
            assert(type(val) == str)
            yield (key, val)

    def print_decrypted(self):
        '''Print the file with all the values decrypted.'''
        for sec in self.sections():
            print("[%s]" % sec)
            for (key, val) in self.items(sec):
                print("%s=%s" % (key, val))
            print()
