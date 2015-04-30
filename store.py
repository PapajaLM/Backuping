__author__ = 'papaja'

import pickle
import os
import hashlib
import shutil
import gzip
import constants
import subprocess
import tempfile
from stat import *
from backup_lib import BackupObject
from backup_lib import ExistingBackup
from backup_lib import objects_init
from CodernityDB.database import Database
from CodernityDB.hash_index import HashIndex
from CodernityDB.database import RecordNotFound, RecordDeleted
from hashlib import md5

class WithHashIndex(HashIndex):

    def __init__(self, *args, **kwargs):
        kwargs['key_format'] = '16s'
        super(WithHashIndex, self).__init__(*args, **kwargs)

    def make_key_value(self, data):
        value = data['hash']
        return md5(value).digest(), None

    def make_key(self, key):
        return md5(key).digest()

class WithPointerIndex(HashIndex):

    def __init__(self, *args, **kwargs):
        kwargs['key_format'] = 'I'
        super(WithPointerIndex, self).__init__(*args, **kwargs)

    def make_key_value(self, data):
        a_val = data.get("pointer")
        if a_val is not None:
            return a_val, None
        return None

    def make_key(self, key):
        return key

class Store():

    def __init__(self, pathname):
        self.store_path = os.path.join(pathname, "target")
        self.init_store_db()
        if not os.path.exists(self.store_path):
            os.mkdir(self.store_path)

    def init_store_dir(self):
        if not os.path.exists(self.store_path):
            os.mkdir(self.store_path)
        objects_path = os.path.join(self.store_path, "objects")
        if not os.path.exists(objects_path):
            os.mkdir(objects_path)
        backups_path = os.path.join(self.store_path, "backups")
        if not os.path.exists(backups_path):
            os.mkdir(backups_path)
        journal_path = os.path.join(self.store_path, "journal")
        if not os.path.exists(journal_path):
            os.mkdir(journal_path)
        journal_objects_path = os.path.join(self.store_path, "journal/objects")
        if not os.path.exists(journal_objects_path):
            os.mkdir(journal_objects_path)
        journal_backups_path = os.path.join(self.store_path, "journal/backups")
        if not os.path.exists(journal_backups_path):
            os.mkdir(journal_backups_path)

    def init_store_db(self):
        self.db = Database(os.path.join(self.store_path, "store.db"))
        if not self.db.exists():
            self.db.create()
            self.db.add_index(WithHashIndex(self.db.path, "hash"))
            self.db.add_index(WithPointerIndex(self.db.path, "pointer"))
        else:
            self.db.open()


    def get_path(self):
        return self.store_path #volania napr. BackupObject.new...(... , target.get_path())

    def get_backup_path(self, backup_name):
        backup_path = os.path.join(self.store_path, "backups")
        return os.path.join(backup_path, backup_name)

    def get_journal_backup_path(self, backup_name):
        backup_path = os.path.join(self.get_journal_path(), "backups")
        return os.path.join(backup_path, backup_name)

    def get_journal_backup_path(self, backup_name):
        backup_path = os.path.join(self.get_journal_path(), "backups")
        return os.path.join(backup_path, backup_name)

    def get_object_path(self, hash):
        object_path = os.path.join(self.store_path, "objects")
        return os.path.join(object_path, hash + ".data")

    def get_journal_object_path(self, hash):
        object_path = os.path.join(self.get_journal_path(), "objects")
        return os.path.join(object_path, hash + ".data")

    def get_object_header_path(self, hash):
        object_header_path = os.path.join(self.store_path, "objects")
        return os.path.join(object_header_path, hash + ".meta")

    def get_journal_object_header_path(self, hash):
        object_header_path = os.path.join(self.get_journal_path(), "objects")
        return os.path.join(object_header_path, hash + ".meta")

    def get_backups_path(self):
        return os.path.join(self.store_path, "backups")

    def get_latest_path(self):
        latest_tmp_path = os.path.join(self.store_path, "backups")
        return os.path.join(latest_tmp_path, "latest")

    def get_journal_latest_path(self):
        latest_tmp_path = os.path.join(self.get_journal_path(), "backups")
        return os.path.join(latest_tmp_path, "latest")

    def get_journal_path(self):
        return os.path.join(self.store_path, "journal")

    def get_all_backups(self):
        backups_path = os.path.join(self.store_path, "backups")
        backups = os.listdir(backups_path)
        if "latest" in backups:
            backups.remove("latest")
        return backups

    def is_journal_complete(self):
        journal_path = self.get_journal_path()
        if (os.path.exists(journal_path)):
            if (os.path.isfile(os.path.join(journal_path, "journal_complete"))):
                return True
            elif (os.path.isfile(os.path.join(journal_path, "journal_incomplete"))):
                print("Clearing Journal")
                self.remove_incomplete_journal()
                os.remove(os.path.join(journal_path, "journal_incomplete"))
                return False
        return False

    def remove_incomplete_journal(self):
        journal_path = self.get_journal_path()
        for file_object in os.listdir(os.path.join(journal_path, "objects")):
            os.remove(os.path.join(journal_path, "objects", file_object))
        for file_object in os.listdir(os.path.join(journal_path, "backups")):
            os.remove(os.path.join(journal_path, "backups", file_object))

    def write_to_journal(self, command):
        journal_path = self.get_journal_path()
        with open(os.path.join(journal_path, "journal_incomplete"), "a") as TF:
            TF.write(command + "\n")
            TF.close()

    def finish_journal(self):
        if os.path.exists(os.path.join(self.get_journal_path(), "journal_incomplete")):
            journal_file = open(os.path.join(self.get_journal_path(), "journal_incomplete"), "r+")
            uniqlines = set(journal_file.readlines())
            journal_file.close()
            journal_file = open(os.path.join(self.get_journal_path(), "journal_incomplete"), "w")
            journal_file.writelines(uniqlines)
            journal_file.close()
            self.file_rename(os.path.join(self.get_journal_path(), "journal_incomplete"), "journal_complete")

    def commit(self):
        print("Committing Journal")
        journal_path = self.get_journal_path()
        if (os.path.exists(self.get_latest_path())):
            os.remove(self.get_latest_path())
        if (self.is_journal_complete()):
            with open(os.path.join(journal_path, "journal_complete"), "rb") as TF:
                for command in TF:
                    words = command.split()
                    if (words[0] == "move"):
                        shutil.move(words[1], words[2])
                        #os.rename(words[1], words[2])
                    elif (words[0] == "remove"):
                        os.remove(words[1])
                TF.close()
            os.remove(os.path.join(journal_path, "journal_complete"))

    @staticmethod
    def file_rename(old_name, new_name):
        new_file_name = os.path.join(os.path.dirname(old_name), new_name)
        os.rename(old_name, new_file_name)

    def save_file(self, source_path, name, previous_hash = None, block_size = constants.CONST_BLOCK_SIZE):
        file_hash = hashlib.sha1()
        target_file = self.get_journal_object_path(name)
        target_file_header = self.get_journal_object_header_path(name)
        if not previous_hash == None:
            previous_type = self.get_object_type(previous_hash)
            if previous_type == "gz\n" or previous_type == "delta\n" :
                previous_file = self.get_object_file_header(previous_hash, "rb")
                previous_file.readline()
                previous_file.readline()
                sig_size = previous_file.readline()
                sig_data = previous_file.read(int(sig_size))
                deltaProcess = subprocess.Popen(['rdiff', 'delta', '-', source_path], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                deltaProcess.stdin.write(sig_data)
                deltaProcess.stdin.close()
                with gzip.open(target_file, "wb") as TF: #bol gzip
                    while True:
                        deltaData = deltaProcess.stdout.read(16)
                        if deltaData:
                            file_hash.update(deltaData)
                            TF.write(deltaData)
                        else:
                             with open(target_file_header, "wb") as THF:
                                THF.write("delta\n")
                                THF.write("signature\n")
                                sigProcess = subprocess.Popen(['rdiff', 'signature', source_path], stdout=subprocess.PIPE)
                                signature, signatureErr = sigProcess.communicate()
                                if (signatureErr is None):
                                    THF.write(str(len(signature)))
                                    THF.write("\n")
                                    THF.write(signature)
                                else:
                                    THF.write(str(0))
                                THF.write("\n")
                                THF.write("previous\n")
                                THF.write(previous_hash)
                                THF.close()
                                self.file_rename(target_file, file_hash.hexdigest() + ".data")
                                self.file_rename(target_file_header, file_hash.hexdigest() + ".meta")
                                break
                    TF.close()
                    self.write_to_journal("move " + self.get_journal_object_path(file_hash.hexdigest()) + " " + os.path.join(self.store_path, "objects", file_hash.hexdigest() + ".data"))
                    self.write_to_journal("move " + self.get_journal_object_header_path(file_hash.hexdigest()) + " " + os.path.join(self.store_path, "objects", file_hash.hexdigest() + ".meta"))
                return file_hash.hexdigest()
        else:
            with open(source_path, "rb") as SF:
                with gzip.open(target_file, "wb") as TF: #bol gzip
                    while True:
                        block = SF.read(block_size)
                        file_hash.update(block)
                        TF.write(block)
                        if not block:
                            self.file_rename(target_file, file_hash.hexdigest() + ".data")
                            with open(target_file_header, "wb") as THF:
                                THF.write("gz\n")
                                THF.write("signature\n")
                                sigProcess = subprocess.Popen(['rdiff', 'signature', source_path], stdout=subprocess.PIPE)
                                signature, signatureErr = sigProcess.communicate()
                                if (signatureErr is None):
                                    THF.write(str(len(signature)))
                                    THF.write("\n")
                                    THF.write(signature)
                                else:
                                    THF.write(str(0))
                                self.file_rename(target_file_header, file_hash.hexdigest() + ".meta")
                                THF.close()
                            break
                    TF.close()
                    self.write_to_journal("move " + self.get_journal_object_path(file_hash.hexdigest()) + " " + os.path.join(self.store_path, "objects", file_hash.hexdigest() + ".data"))
                    self.write_to_journal("move " + self.get_journal_object_header_path(file_hash.hexdigest()) + " " + os.path.join(self.store_path, "objects", file_hash.hexdigest() + ".meta"))
                SF.close()
            return file_hash.hexdigest()

    def save_directory(self, pi, hash_name):
        with self.get_journal_object_file(hash_name, "wb") as DF:
            with self.get_journal_object_file_header(hash_name, "wb") as DHF:
                DHF.write("directory\n")
                DF.write(pi)
                DF.close()
                DHF.close()
        self.write_to_journal("move " + DF.name + " " + os.path.join(self.store_path, "objects", hash_name + ".data"))
        self.write_to_journal("move " + DHF.name + " " + os.path.join(self.store_path, "objects", hash_name + ".meta"))

    def save_link(self, link, hash_name):
        with self.get_journal_object_file(hash_name.hexdigest(), "wb") as DF:
            with self.get_journal_object_file_header(hash_name.hexdigest(), "wb") as DHF:
                DHF.write("link\n")
                DHF.write("signature\n")
                DHF.write(str(0))
                DHF.write("\n")
                DF.write(link)
                DHF.close()
            DF.close()
        self.write_to_journal("move " + DF.name + " " + os.path.join(self.store_path, "objects", hash_name.hexdigest() + ".data"))
        self.write_to_journal("move " + DHF.name + " " + os.path.join(self.store_path, "objects", hash_name.hexdigest() + ".meta"))

    def save_data(self, file_name, data):
        with open(file_name, "wb") as BF:
            BF.write(data)
            BF.close()
        self.write_to_journal("move " + BF.name + " " + os.path.join(self.store_path, "backups"))

    def get_object_file(self, hash, mode):
        type = self.get_object_type(hash)
        if type == "gz" or type == "delta":
            return gzip.open(self.get_object_path(), mode)
        return open(self.get_object_path(hash), mode)

    def get_journal_object_file(self, hash, mode):
        return open(self.get_journal_object_path(hash), mode)

    def get_object_file_header(self, hash, mode):
        return open(self.get_object_header_path(hash), mode)

    def get_journal_object_file_header(self, hash, mode):
        return open(self.get_journal_object_header_path(hash), mode)

    def get_object_type(self, hash):
        with self.get_object_file_header(hash, "rb") as HF:
            object_type = HF.readline()
            HF.close()
            return object_type

    def get_object(self, source_path, hash, side_dict):
        return StoreObject.create(source_path, self, side_dict)

    def get_unzipped_tempFile(self, hash, tempFile):
        gzipFile = gzip.open(self.get_object_path(hash))
        temp = open(tempFile.name, "w+")
        while True:
            block = gzipFile.read()
            temp.write(block)
            if not block:
                break
        temp.seek(0)
        gzipFile.close()
        return temp

    def get_hash(self, src_file, block_size = constants.CONST_BLOCK_SIZE):
        file_hash = hashlib.sha1()
        with open(src_file, "rb") as SF:
            while True:
                block = SF.read(block_size)
                file_hash.update(block)
                if not block : break
            SF.close()
        return file_hash.hexdigest()

    def incIndex(self, hash):
        try:
            element = self.db.get('hash', hash, with_doc=True)
            element = element['doc']
            element['pointer'] = element['pointer'] + 1
            self.db.update(element)
        except RecordNotFound:
            self.db.insert({'hash':hash, 'pointer':1})
            return 1
        return element['pointer']

    def decIndex(self, hash):
        try:
            element = self.db.get('hash', hash, with_doc=True)
            element = element['doc']
            element['pointer'] = element['pointer'] - 1
            print element
            if element['pointer'] == 0:
                self.db.delete(element)
            else:
                self.db.update(element)
        except RecordNotFound:
            print "record not found: " + hash
            return -1
        return element['pointer']

    def rebuildDB(self):
        self.db.destroy()
        self.init_store_db()
        backups = self.get_all_backups()
        for backup in backups:
            tmp = ExistingBackup('', self, backup)
            tmp.recovery_backup(True)

    def removeObject(self, hash):
        index = self.decIndex(hash)
        if index == 0:
            self.write_to_journal("remove " + self.get_object_path(hash))
            self.write_to_journal("remove " + self.get_object_header_path(hash))

    def removeBackup(self, time):
        backup = ExistingBackup("", self, time).get_root_object()
        backup.remove()
        os.remove(self.get_backup_path(time))
        newest = self.getNewestBackupTime()
        if newest != None:
            self.save_data(self.get_journal_latest_path(), newest)
        self.finish_journal()
        self.commit()

    def getNewestBackupTime(self):
        backups_path = self.get_backups_path()
        backups = sorted(os.listdir(backups_path))
        backups.remove("latest")
        if len(backups) > 0:
            return backups[len(backups) - 1]
        return None


class StoreObject(BackupObject):

    @staticmethod
    def create(source_path, store, side_dict):
        #print side_dict
        lstat = side_dict['lstat']
        object_hash = side_dict['hash']
        object_type = store.get_object_type(object_hash).rstrip('\n')
        mode = lstat.st_mode
        if S_ISDIR(mode) and object_type == "directory":
            return StoreDir(source_path, store, lstat, side_dict)
        elif S_ISREG(mode) and object_type == "gz":
            return StoreGzipFile(source_path, store, lstat, side_dict, store.get_object_path(side_dict['hash']))
        elif S_ISREG(mode) and object_type == "raw":
            return StoreRawFile(source_path, store, lstat, side_dict, store.get_object_path(side_dict['hash']))
        elif S_ISREG(mode) and object_type == "delta":
            return StoreDeltaFile(source_path, store, lstat, side_dict, store.get_object_path(side_dict['hash']))
        elif S_ISLNK(mode) and object_type == "link":
            return StoreLnk(source_path, store, lstat, side_dict)
        else:
            # Unknown file
            return None

    def recovery_stat(self, object_path, lstat):
        #os.lchmod(object_path, lstat.st_mode)  AttributeError: 'module' object has no attribute 'lchmod'
        try :
            time = lstat.st_atime, lstat.st_mtime
            os.utime(object_path, time)
        except OSError:
            pass
        try:
            os.chmod(object_path, S_IMODE(lstat.st_mode))
        except OSError:
            pass
        try:
            os.lchown(object_path, lstat.st_uid, lstat.st_gid)
        except OSError:
            pass # doplnit printy / handle exceptetion

    def __init__(self, source_path, store, lstat, side_dict):
        if objects_init : print("Initializing StoreObject ", source_path)
        #print source_path
        BackupObject.__init__(self, source_path, store, lstat)
        self.side_dict = side_dict
        #print self.side_dict
        #print self.name

    def remove(self):
        self.store.removeObject(self.side_dict['hash'])

    def incIndex(self):
        self.store.incIndex(self.side_dict['hash'])


class StoreFile(StoreObject):

    def __init__(self, source_path, store, lstat, side_dict):
        if objects_init : print("Initializing StoreFile (%s)") % source_path
        #print source_path
        StoreObject.__init__(self, source_path, store, lstat, side_dict)

    def recover(self, buildingDB = False, block_size = constants.CONST_BLOCK_SIZE):
        # reverse file_copy()
        if not buildingDB:
            with self.store.get_object_file(self.side_dict['hash'], "rb") as TF:
                #recovery_file = os.path.join(self.source_path)#name)
                with open(self.source_path, "wb") as RF:
                    while True:
                        block = TF.read(block_size)
                        RF.write(block)
                        if not block:
                            break
                    RF.close()
                TF.close()
            self.recovery_stat(self.source_path, self.side_dict['lstat'])
        else:
            self.store.incIndex(self.side_dict['hash'])

class StoreDir(StoreObject):

    #Pomocou tejto metody treba nacitat slovnik objektov v adresari
    #do vhodnej instancnej premennej objektu triedy TargetDir napriklad v konstruktore.
    #Do tohto slovnika (nie do side_dict!) potom pristupuje metoda get_object().
    def __init__(self, source_path, store, lstat , side_dict):
        if objects_init : print("Initializing StoreDir ", source_path)
        #print source_path
        #print target_path
        #print side_dict
        #path = os.path.join(target_path, side_dict['hash'])
        #print path
        self.loaded_dict = self.unpickling(store.get_object_path(side_dict['hash']))
        self.loaded_obj = {}
        StoreObject.__init__(self, source_path, store, lstat, side_dict)
        #print self.side_dict

    def get_file_name(self):
        return self.object

    def get_object(self, name, st_mode):
        # zisti, ci objekt "name" existuje v zalohovanej verzii
        # tohto adresara
        # ak ano, vyrobi prislusny TargetObject
        # ak nie, vrati None
        if name in self.loaded_dict and self.loaded_dict[name]['lstat'].st_mode == st_mode:
            if ('object_' + name) in self.loaded_obj:
                return self.loaded_obj['object_' + name]
            else:
                new_target_object = StoreObject.create(os.path.join(self.source_path, name), self.store, self.loaded_dict[name])
                self.loaded_obj['object_' + name] = new_target_object
                return new_target_object
        else:
            return None

    def get_object_by_path(self, folders, file_name):
        size = len(folders)
        if len(folders) > 0:
            folder = folders.pop(0)
            name = folder
        else:
            name = file_name
        if name in self.loaded_dict:
            if ('object_' + name) in self.loaded_obj:
                if (name == file_name and size == 0):
                    return self.loaded_obj['object_' + name]
                else:
                    return self.loaded_obj['object_' + name].get_object_by_path(folders, file_name)
            else:
                new_store_object = StoreObject.create(os.path.join(self.source_path, name), self.store, self.loaded_dict[name])
                self.loaded_obj['object_' + name] = new_store_object
                if (name == file_name and size == 0):
                    return self.loaded_obj['object_' + name]
                else:
                    return self.loaded_obj['object_' + name].get_object_by_path(folders, file_name)
        else:
            return None

    def unpickling(self, store_path):
        #unpkl_file = os.path.join(target_path, file_name)
        with open(store_path, "rb") as UPF:
            pi = UPF.read()
            UPF.close()
        return_dict = pickle.loads(pi)
        #print return_dict
        return return_dict

    def recover(self, buildingDB = False):
        #prejst slovnik
        # ak dir tak rekurzia
        #inak .recovery_backup
        #passdef recovery_backup(self):
        #for name , in self.side_dict.iteritems():
        # if IS_REG(self.side_dict[key]['lstat'].st_mode):
        if not buildingDB and not os.path.exists(self.source_path):
            os.mkdir(self.source_path)
        print self.loaded_dict
        for store_object_name in self.loaded_dict.iterkeys():
            new_store_object = self.get_object(store_object_name, self.loaded_dict[store_object_name]['lstat'].st_mode)
            new_store_object.recover(buildingDB)#os.path.join(self.source_path, target_object_name))
        # obnovit metadata adresara!!!!!!!!!!!
        if not buildingDB:
            self.recovery_stat(self.source_path, self.side_dict['lstat'])

    def remove(self):
        for store_object_name in self.loaded_dict.iterkeys():
            store_object = self.get_object(store_object_name, self.loaded_dict[store_object_name]['lstat'].st_mode)
            store_object.remove()
        self.store.removeObject(self.side_dict['hash'])

    def incIndex(self):
        for store_object_name in self.loaded_dict.iterkeys():
            store_object = self.get_object(store_object_name, self.loaded_dict[store_object_name]['lstat'].st_mode)
            # self.store.incIndex(self.loaded_dict[store_object_name]['hash'])
            store_object.incIndex()
        self.store.incIndex(self.side_dict['hash'])

class StoreLnk(StoreObject):

    def __init__(self, source_path, store, lstat, side_dict):
        if objects_init : print("Initializing StoreLnk (%s)") % source_path
        #print source_path
        StoreObject.__init__(self, source_path, store, lstat, side_dict)

    def read_backuped_lnk(self):
        with self.store.get_object_file(self.side_dict['hash'], "rb") as TF:
            backuped_link_name = TF.read()
        return backuped_link_name

    def recovery_stat(self, object_path, lstat):
        try:
            os.lchown(object_path, lstat.st_uid, lstat.st_gid)
        except OSError:
            pass # dolnit printy / handle exceptetion

    def recover(self, buildingDB = False):
        if not buildingDB:
            os.symlink(self.read_backuped_lnk(), self.source_path )
            self.recovery_stat(self.source_path, self.side_dict['lstat'])
        else:
            self.store.incIndex(self.side_dict['hash'])

class StoreRawFile(StoreFile, file):

    def __init__(self, source_path, store, lstat, side_dict, file_name):
        if objects_init : print("Initializing StoreRawFile (%s)") % source_path
        StoreObject.__init__(self, source_path, store, lstat, side_dict)
        if type(file_name) == file:
            self.__dict__.update(file.__dict__)
        else:
            file.__init__(self, file_name)


class StoreGzipFile(StoreFile, gzip.GzipFile):#gzip.GzipFile):

    def __init__(self, source_path, store, lstat, side_dict, file_name):
        if objects_init : print("Initializing StoreGzipFile (%s)") % source_path
        StoreObject.__init__(self, source_path, store, lstat, side_dict)
        if type(file_name) == gzip.GzipFile:
            self.__dict__.update(file_name.__dict__)
        else:
            # gzip.GzipFile.__init__(self, file_name)
            gzip.GzipFile.__init__(self, file_name)
            self.close()

    def open(self):
        gzip.GzipFile.__init__(self, self.name)

class StoreDeltaFile(StoreFile, file):

    def __init__(self, source_path, store, lstat, side_dict, file_name):
        if objects_init : print("Initializing StoreDeltaFile (%s)") % source_path
        StoreObject.__init__(self, source_path, store, lstat, side_dict)
        # if type(file_name) == file:
        #     self.__dict__.update(file.__dict__)
        # else:
        #     file.__init__(self, file_name)
        self.patched_file = self.get_patched_file(self.side_dict['hash'])
        # print self.__dict__.viewitems()
        # print self.patched_file
        # self.__dict__.update(self.patched_file.__dict__)
            # self.close()

    def open(self):
        # file.__init__(self, self.name)
        self.patched_file = self.get_patched_file(self.side_dict['hash'])

    def read(self, size=None):
        return self.patched_file.read(size)

    def seek(self, offset, whence=None):
        if self.patched_file.closed:
             self.open()
        self.patched_file.seek(offset)

    def close(self):
        self.patched_file.close()

    def get_previous_hash(self, hash):
        with self.store.get_object_file_header(hash, "rb") as THF:
            THF.readline()
            THF.readline()
            sig_size = THF.readline()
            THF.read(int(sig_size))
            THF.readline()
            if THF.readline() == "previous\n":
                previous_hash = THF.readline()
            else:
                previous_hash = None
            THF.close
            return previous_hash

    def get_base_file_hash(self, hash = None):
        previous_hash = self.get_previous_hash
        if previous_hash == None:
            return hash
        else:
            self.get_base_file_hash(previous_hash)

    def get_list_of_hashes(self, hash):
        list = [hash]
        previous_hash = self.get_previous_hash(hash)
        while (previous_hash != None):
            list.append(previous_hash)
            previous_hash = self.get_previous_hash(previous_hash)
        return list

    def get_patched_file(self, hash):
        list = self.get_list_of_hashes(hash)
        base_file_hash = list.pop()
        first = 1
        tempFile = tempfile.NamedTemporaryFile()
        tempFile2 = tempfile.NamedTemporaryFile()
        tempFile3 = tempfile.NamedTemporaryFile()
        temp = open(tempFile.name, "w+")
        while (len(list) > 0 or not first == 0):
            first = 0
            if not base_file_hash == None:
                patchProcess = subprocess.Popen(['rdiff', 'patch', self.store.get_unzipped_tempFile(base_file_hash, tempFile2).name, self.store.get_unzipped_tempFile(list.pop(), tempFile3).name, '-'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
                base_file_hash = None
            else:
                patchProcess = subprocess.Popen(['rdiff', 'patch', temp.name, self.store.get_unzipped_tempFile(list.pop(), tempFile2).name, '-'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
            patch, patchErr = patchProcess.communicate()
            temp.close()
            tempFile.close()
            tempFile2.close()
            tempFile3.close()
            if (patchErr is None):
                tempFile = tempfile.NamedTemporaryFile()
                temp = open(tempFile.name, "w+")
                temp.write(patch)
        temp.seek(0)
        return temp

    def recover(self, buildingDB = False, block_size = constants.CONST_BLOCK_SIZE):
        # reverse file_copy()
        if not buildingDB:
            with self.get_patched_file(self.side_dict['hash']) as TF:
                #recovery_file = os.path.join(self.source_path)#name)
                with open(self.source_path, "wb") as RF:
                    while True:
                        block = TF.read(block_size)
                        RF.write(block)
                        if not block:
                            break
                    RF.close()
                TF.close()
            self.recovery_stat(self.source_path, self.side_dict['lstat'])
        else:
            self.store.incIndex(self.side_dict['hash'])

    def remove(self):
        list = self.get_list_of_hashes(self.side_dict['hash'])
        for hash in list:
            self.store.removeObject(hash)

    def incIndex(self):
        list = self.get_list_of_hashes(self.side_dict['hash'])
        for hash in list:
            self.store.incIndex(hash)