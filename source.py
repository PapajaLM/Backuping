__author__ = 'papaja'

import pickle
import os
import hashlib
from stat import *
from backup_lib import BackupObject
from backup_lib import verbose
from backup_lib import objects_init

class SourceObject(BackupObject):

    @staticmethod
    def create(source_path, store, target_object):
        lstat = os.lstat(source_path)
        mode = lstat.st_mode
        if S_ISDIR(mode):
                return SourceDir(source_path, store, lstat, target_object)
        elif S_ISREG(mode):
                return SourceFile(source_path, store, lstat, target_object)
        elif S_ISLNK(mode):
                return SourceLnk(source_path, store, lstat, target_object)
        else:
                # Unknown file
                return None

    def __init__(self, source_path, store, lstat, target_object):
        #if objects_init : print "Initializing SourceFile (%s)" % source_path
        BackupObject.__init__(self, source_path, store, lstat)
        self.target_object = target_object


    def exist_backup(self):
        file_hash = self.store.get_hash(self.source)
        return os.path.exists(self.store.get_object_path()) ####################################

    def compare_stat(self, object_stat, backuped_stat):
        return (object_stat.st_size == backuped_stat.st_size and #nezmenil velkost
                object_stat.st_uid == backuped_stat.st_uid and # nezmenil uziv
                object_stat.st_gid == backuped_stat.st_gid and # nezmenil skupinu
                object_stat.st_mtime == backuped_stat.st_mtime and # posledna modifikacia
                object_stat.st_mode == backuped_stat.st_mode and
                object_stat.st_ctime == backuped_stat.st_ctime) # last metadata change time


class SourceFile(SourceObject):

    def __init__(self, source_path, store, lstat, target_object):
        if objects_init : print("Initializing SourceFile (%s)") % source_path
        #print source_path
        SourceObject.__init__(self, source_path, store, lstat, target_object)

    def save_file(self):
        return self.store.save_file(self.source_path, self.name)

    #REFACTORED
    def backup(self):
        # ak sa zmenil mtime, tak ma zmysel pozerat sa na obsah suboru
        # inak sa mozno zmenili zaujimave metadata
        if self.target_object != None:
            if not self.compare_stat(self.lstat, self.target_object.lstat): # ak sa nerovnaju lstaty
                if (self.lstat.st_mtime == self.target_object.lstat.st_mtime
                    and self.lstat.st_size == self.target_object.lstat.st_size):
                    if verbose : print("Lnk mTime bez zmeny. return novy side_dict(stary_hash) !")
                    # rovanky mtime
                    # vyrob side dict stary hash + aktualny lstat
                    return self.make_side_dict(self.target_object.side_dict['hash']) #stary hash
                else:
                    # rozny mtime
                    new_hash = self.store.get_hash(self.source_path) # spocitaj hash a porovnaj
                    if (new_hash == self.target_object.side_dict['hash']
                        or os.path.exists(self.store.get_object_path(new_hash))):
                        if verbose : print("File mTime zmeneny. return novy side_dict(novy_hash) !")
                        return self.make_side_dict(new_hash)
                    else:
                        if verbose : print("File Novy object zalohy.")
                        hash = self.save_file()
                        return self.make_side_dict(hash)
            else:
                if verbose : print("Lnk mTime zmeneny. rovnake meta")
                return self.target_object.side_dict # ak sa rovnaju staty
        else:
            if verbose : print("File Novy object zalohy.")
            hash = self.save_file()
            return self.make_side_dict(hash)


class SourceDir(SourceObject):

    def __init__(self, source_path, store, lstat, target_object):
        if objects_init : print("Initializing SourceDir (%s)") % source_path
        #print source_path
        SourceObject.__init__(self, source_path, store, lstat, target_object)
        if self.target_object != None: print(self.target_object.side_dict)

    #REFACTORED
    def pickling(self, input_dict):
        pi = pickle.dumps(input_dict)
        hash_name = hashlib.sha1(pi).hexdigest()
        if (self.target_object == None
            or not os.path.exists(self.store.get_object_path(hash_name))): #or ...hashe sa nerovnaju...:
            with self.store.get_object_file(hash_name, "wb") as DF:
                with self.store.get_object_file_header(hash_name, "wb") as DHF:
                    DHF.write("directory\n")
                    DF.write(pi)
                    DF.close()
                    DHF.close()
        return hash_name

    def backup(self):
        #Metoda SourceDir.incremental_backup() je zmatocna.
        #Ak neexistuje self.target_object (teda stara cielova verzia aktualneho adresara),
        #metodu initial_backup() treba volat na podobjekt v adresari
        #(vytvoreny pomocou SourceObject.create(next_path,self.target,None)),
        #nie na (self teda na aktualny adresar). Takto spraveny incremental_backup()
        #bude potom v pripade neexistujuceho target_object fungovat rovnako
        #ako initial_backup() a teda nemusite mat dve metody
        #(ale podobne treba spravit aj incremental_backup() v SourceFile a SourceLnk).
        main_dict = {}
        for F in os.listdir(self.source_path):
                next_path = os.path.join(self.source_path,F)
                if self.target_object != None:
                    oldF = self.target_object.get_object(F)
                else:
                    oldF = None
                new_object = SourceObject.create(next_path, self.store, oldF)
                side_dict = new_object.backup()
                main_dict[F] = side_dict
        #print main_dict
        hash = self.pickling(main_dict)
        return self.make_side_dict(hash)

class SourceLnk(SourceObject):

    def __init__(self, source_path, store, lstat, target_object):
        if objects_init : print("Initializing SourceLnk (%s)") % source_path
        #print source_path
        SourceObject.__init__(self, source_path, store, lstat, target_object)

    #REFACTORED
    def make_lnk(self):
        link_target = os.readlink(self.source_path)
        hash_name = hashlib.sha1()
        hash_name.update(link_target)
        with self.store.get_object_file(hash_name.hexdigest(), "wb") as DF:
            with self.store.get_object_file_header(hash_name.hexdigest(), "wb") as DHF:
                DHF.write("link\n")
                DHF.write("signature\n")
                DHF.write(str(0))
                DHF.write("\n")
                DF.write(link_target)
                DHF.close()
            DF.close()
        return hash_name.hexdigest()

    #def initial_backup(self):
    #            return self.make_side_dict(self.make_lnk())

    def backup(self):
        if self.target_object != None:
            if not self.compare_stat(self.lstat, self.target_object.lstat): # ak sa nerovnaju lstaty
                if (self.lstat.st_mtime == self.target_object.lstat.st_mtime
                    and self.lstat.st_size == self.target_object.lstat.st_size):
                    if verbose : print("Lnk mTime bez zmeny. return novy side_dict(stary_hash) !")
                    # rovanky mtime
                    # vyrob side dict stary hash + aktualny lstat
                    return self.make_dict(self.target_object.side_dict[self.name]['hash']) #stary hash
                else:
                    # rozny mtime
                    link_target = os.readlink(self.source_path)
                    new_hash = hashlib.sha1(link_target).hexdigest() # spocitaj hash a porovnaj
                    if (new_hash == self.target_object.side_dict[self.name]['hash']
                        or os.path.exists(self.store.get_object_path(new_hash))):
                        if verbose : print("Lnk mTime zmeneny. return novy side_dict(novy_hash) !")
                        return self.make_dict(new_hash)
                    else:
                        if verbose : print("Lnk Novy object zalohy !")
                        return self.make_side_dict(self.make_lnk())
            else:
                if verbose : print("Lnk mTime zmeneny. rovnake meta")
                return self.target_object.side_dict # ak sa rovnaju staty
        else:
            if verbose : print("Lnk Novy object zalohy.")
            return self.make_side_dict(self.make_lnk())