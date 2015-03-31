from datetime import datetime as datum
import pickle
import os

verbose = True
#print "verbose = (%s)" % (verbose)
debug = True
#print "debug = (%s)" % (verbose)
objects_init = True
#print "objects_init = (%s)" % (objects_init)


class Backup():

    def __init__(self, source_path, store):
        #self.time = self.get_time() # zbytocne ?!
        self.source_path = source_path
        self.store = store
        #self.backup_time = existing_backup.max_time # napr. 2012-12-12T12:12 / v tedy sa pouzije namiesot self.time

    def get_time(self):
        return datum.now().strftime('%Y-%m-%dT%H:%M:%S')

    def make_backup(self, time, side_dict):
        pickled_dict = pickle.dumps(side_dict)
        file_name = self.store.get_journal_backup_path(time)
        self.store.save_data(file_name, pickled_dict)
                        
    def get_backup(self, time): 
        file_name = self.store.get_backup_path(time)
        with open(file_name, "rb") as BF:
                load_dict=BF.read()
                BF.close()
        side_dict = pickle.loads(load_dict)
        return side_dict

    def update_latest_backup(self, time):# neskor v target
        file_name = self.store.get_journal_latest_path()
        self.store.save_data(file_name, time)

    def read_latest_backup(self, store):# neskor v target
        file_name = store.get_latest_path()
        with open(file_name, "rb") as LF:
            time = LF.read()
            LF.close()
        return time

    def backup(self):
        # New Backup
        pass
 
    def recover(self):
        pass
        

class NewBackup(Backup):
    #back = NewBackup('/home/kmm/Plocha/source',target.get_path()) + None
    def __init__(self, source_path, store, existing_backup = None):
        if objects_init : print("Initializing NewBackup (%s)") % existing_backup
        self.existing_backup = existing_backup
        Backup.__init__(self, source_path, store)

    def backup(self):
        from source import SourceObject
        # vytvori novu zalohu
        self.store.is_journal_complete()
        self.store.init_store_dir()
        if self.existing_backup == None:
            trg_object = None
        else:
            trg_object = self.existing_backup.get_root_object()
        src_object = SourceObject.create(self.source_path, self.store, trg_object)
        new_side_dict = src_object.backup()
        backup_time = self.get_time()
        self.make_backup(backup_time, new_side_dict)
        self.update_latest_backup(backup_time)
        self.store.finish_journal()
        self.store.commit()
    

class ExistingBackup(Backup):
    #nacitanie existujucich zaloh
    
    def __init__(self, source_path, store, backup_time):
        if backup_time == "latest":
            self.backup_time = self.read_latest_backup(store)
        else:
            self.backup_time = backup_time
        if objects_init : print("Initializing ExistingBackup", self.backup_time)
        Backup.__init__(self, source_path, store)

    def backup(self):
        pass

    def get_root_object(self):
        from store import StoreObject
        side_dict = self.get_backup(self.backup_time)
        return StoreObject.create(self.source_path, self.store, side_dict)
        
    #Recovery = ExistingBackup('/home/kmm/Plocha/source',target.get_path(),'2013-03-29T18:57:12')
    #ktoru zalohu chceme obnovit sa bude rieit na urvovni scriptu nie samtotneho backupera
    # self.name obsahuje teraz 2013-29.... zaloha ktoru chcem obnovit
    # self.source - urcuje miesto kam chcem zalohu obnovit
    
    def recovery_backup(self, buildingDB = False):
        from store import StoreObject
        #max_time = self.get_latest_time(self.target)
        side_dict = self.get_backup(self.backup_time)
        #print side_dict
        recovery_obj = StoreObject.create(self.source_path, self.store, side_dict)
        recovery_obj.recover(buildingDB)

        
class BackupObject():

    @staticmethod
    # TypeError: readonly attribute
    def make_lstat(lstat):
        #print lstat
        lstat.st_dev = None
        lstat.st_nlink = None
        lstat.st_atime = None
        return lstat

    def __init__(self, source_path, store, lstat):
        #if objects_init : print "Initializing BackupObject (%s)" % source_path
        self.source_path = source_path
        self.store = store
        self.lstat = lstat # self.make_lstat(lstat) ... nefunguje vid hore
        self.source_dir = os.path.dirname(source_path)
        self.file_name = os.path.basename(source_path)

    def get_file_name(self):
        return self.file_name

    def make_side_dict(self, hash):
        return { 'lstat': self.lstat,
                 'hash': hash }

    def initial_backup(self):
        #first Backup
        pass

    def incremental_backup(self):
        # Incremental Backup
        pass

    def recover(self):
        # recovery Backup
        pass

    def file_rename(self, old_name, new_name):
        new_file_name = os.path.join(os.path.dirname(old_name), new_name)
        os.rename(old_name, new_file_name)

