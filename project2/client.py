"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import json

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object, username)
        self.permanent_encryption_key = self.get_permanent_keys()[:32]
        self.permanent_mac_key = self.get_permanent_keys()[32:64]
        self.permanent_filename_key = self.get_permanent_keys()[64:]

    def encrypt_then_mac(self, encryption_key, mac_key, message):
        iv = self.crypto.get_random_bytes(16)
        ciphertext = self.crypto.symmetric_encrypt(message, encryption_key, cipher_name='AES', mode_name='CBC', IV=iv)
        mac = self.crypto.message_authentication_code(ciphertext, mac_key, hash_name='SHA256')
        return iv + ciphertext + mac

    def check_then_decrypt(self, encryption_key, mac_key, ciphertext_with_mac):
        mac = ciphertext_with_mac[-64:]
        iv = ciphertext_with_mac[:32]
        ciphertext = ciphertext_with_mac[32:-64]
        mac_expected = self.crypto.message_authentication_code(ciphertext, mac_key, hash_name='SHA256')
        if mac_expected == mac:
            return self.crypto.symmetric_decrypt(ciphertext, encryption_key, cipher_name='AES', mode_name='CBC', IV=iv)
        else:
            raise IntegrityError

    def get_permanent_keys(self):
        keys = self.storage_server.get(self.username + '/permanent_keys/keys')
        signature = self.storage_server.get(self.username + '/permanent_keys/signature')
        if keys is None or signature is None:
            return self.initialize_permanent_keys()
        else:
            if self.crypto.asymmetric_verify(keys, signature, self.rsa_priv_key):
                return self.crypto.asymmetric_decrypt(keys, self.elg_priv_key);
            else:
                raise IntegrityError

    def initialize_permanent_keys(self):
        permanent_encryption_key = self.crypto.get_random_bytes(16)
        permanent_mac_key = self.crypto.get_random_bytes(16)
        permanent_filename_key = self.crypto.get_random_bytes(16)
        permanent_keys = permanent_encryption_key + permanent_mac_key + permanent_filename_key
        encrypted_permanent_keys = self.crypto.asymmetric_encrypt(permanent_keys, self.elg_priv_key)
        signature_permanent_keys = self.crypto.asymmetric_sign(encrypted_permanent_keys, self.rsa_priv_key)
        self.storage_server.put(self.username + '/permanent_keys/keys', encrypted_permanent_keys)
        self.storage_server.put(self.username + '/permanent_keys/signature', signature_permanent_keys)
        return permanent_keys

    def upload(self, name, value):
        try:
            pointer_id = self.crypto.message_authentication_code(name, self.permanent_filename_key, hash_name='SHA256')
            if self.storage_server.get(self.username + "/keys/" + pointer_id) is None:
                file_id = self.crypto.get_random_bytes(16)
                file_pointer = self.username + "/data/" + file_id
                file_encryption_key = self.crypto.get_random_bytes(16)
                file_mac_key = self.crypto.get_random_bytes(16)
                file_info = file_pointer + file_encryption_key + file_mac_key
                encrypted_file_info = self.encrypt_then_mac(self.permanent_encryption_key, self.permanent_mac_key, file_info)
                final_file_info = encrypted_file_info + self.crypto.message_authentication_code(encrypted_file_info + name,
                                                                                                self.permanent_filename_key,
                                                                                                hash_name='SHA256')
                encrypted_file = self.encrypt_then_mac(file_encryption_key, file_mac_key, value)
                self.storage_server.put(self.username + "/keys/" + pointer_id, "[POINTER]" + final_file_info)
                self.storage_server.put(file_pointer, "[DATA]" + encrypted_file)
                self.storage_server.put(self.username + "/children_of/" + pointer_id,
                                        self.encrypt_then_mac(self.permanent_encryption_key, self.permanent_mac_key,
                                                              json.dumps({})))
            else:
                final_file_info = self.storage_server.get(self.username + "/keys/" + pointer_id)[9:]
                encrypted_file_info = final_file_info[:-64]
                expected_mac = self.crypto.message_authentication_code(encrypted_file_info + name,
                                                                       self.permanent_filename_key, hash_name='SHA256')
                if expected_mac == final_file_info[-64:]:
                    info = self.check_then_decrypt(self.permanent_encryption_key, self.permanent_mac_key,
                                                   encrypted_file_info)
                    info = self.findinfo(info)
                    mac_key = info[-32:]
                    encryption_key = info[-64:-32]
                    pointer = info[:-64]
                    new_file = self.encrypt_then_mac(encryption_key, mac_key, value)
                    self.storage_server.put(pointer, "[DATA]" + new_file)
                else:
                    raise IntegrityError
        except:
            raise IntegrityError

    def download(self, name):
        try:
            pointer_id = self.crypto.message_authentication_code(name, self.permanent_filename_key, hash_name='SHA256')
            final_file_info = self.storage_server.get(self.username + "/keys/" + pointer_id)[9:]
            encrypted_file_info = final_file_info[:-64]
            expected_mac = self.crypto.message_authentication_code(encrypted_file_info + name,
                                                                   self.permanent_filename_key, hash_name='SHA256')
            if expected_mac == final_file_info[-64:]:
                info = self.check_then_decrypt(self.permanent_encryption_key, self.permanent_mac_key, encrypted_file_info)
                info = self.findinfo(info)
                mac_key = info[-32:]
                encryption_key = info[-64:-32]
                pointer = info[:-64]
                encrypted_file = self.storage_server.get(pointer)[6:]
                file = self.check_then_decrypt(encryption_key, mac_key, encrypted_file)
                return file;
            else:
                raise IntegrityError
        except KeyError:
            return None
        except TypeError:
            return None
        except:
            raise IntegrityError

    def findinfo(self, info):
        mac_key = info[-32:]
        encryption_key = info[-64:-32]
        pointer = info[:-64]
        while (self.storage_server.get(pointer).startswith("[POINTER]")):
            encrypted_info = self.storage_server.get(pointer)[9:]
            info = self.check_then_decrypt(encryption_key, mac_key, encrypted_info)
            mac_key = info[-32:]
            encryption_key = info[-64:-32]
            pointer = info[:-64]
        return info


    def share(self, user, name):
        pointer_id = self.crypto.message_authentication_code(name, self.permanent_filename_key, hash_name='SHA256')
        final_file_info = self.storage_server.get(self.username + "/keys/" + pointer_id)[9:]
        encrypted_file_info = final_file_info[:-64]
        expected_mac = self.crypto.message_authentication_code(encrypted_file_info + name, self.permanent_filename_key,
                                                               hash_name='SHA256')
        if expected_mac == final_file_info[-64:]:
            file_info = self.check_then_decrypt(self.permanent_encryption_key, self.permanent_mac_key, encrypted_file_info)
            file_mac_key = file_info[-32:]
            file_encryption_key = file_info[-64:-32]
            file_pointer = file_info[:-64]
        else:
            raise IntegrityError
        share_node_id = self.crypto.get_random_bytes(16)
        share_node_encryption_key = self.crypto.get_random_bytes(16)
        share_node_mac_key = self.crypto.get_random_bytes(16)
        share_node_content = file_pointer + file_encryption_key + file_mac_key
        encrypted_share_node_content = self.encrypt_then_mac(share_node_encryption_key,share_node_mac_key, share_node_content)
        self.storage_server.put(share_node_id, "[POINTER]" + encrypted_share_node_content)
        message = share_node_id + share_node_encryption_key + share_node_mac_key
        encrypted_message = self.crypto.asymmetric_encrypt(message, self.pks.get_encryption_key(user))
        signature = self.crypto.asymmetric_sign(encrypted_message, self.rsa_priv_key)
        if not self.storage_server.get(self.username + "/children_of/" + pointer_id) is None:
            current_dict = json.loads(self.check_then_decrypt(self.permanent_encryption_key, self.permanent_mac_key,
                                                              self.storage_server.get(self.username + "/children_of/" + pointer_id)))
            current_dict[user] = message
            self.storage_server.put(self.username + "/children_of/" + pointer_id,
                                    self.encrypt_then_mac(self.permanent_encryption_key, self.permanent_mac_key,
                                                          json.dumps(current_dict)))
        return encrypted_message + signature

    def receive_share(self, from_username, newname, message):
        try:
            signature = message[-512:]
            if self.crypto.asymmetric_verify(message[:-512], signature, self.pks.get_signature_key(from_username)):
                share_node_info = self.crypto.asymmetric_decrypt(message[:-512], self.elg_priv_key)
                encrypted_share_node_info = self.encrypt_then_mac(self.permanent_encryption_key, self.permanent_mac_key,
                                                                  share_node_info)
                final_share_node_info = encrypted_share_node_info + self.crypto.message_authentication_code(encrypted_share_node_info + newname,
                                                                                                            self.permanent_filename_key,
                                                                                                            hash_name = 'SHA256')
                pointer_id = self.crypto.message_authentication_code(newname, self.permanent_filename_key, hash_name='SHA256')
                self.storage_server.put(self.username + "/keys/" + pointer_id, "[POINTER]" + final_share_node_info)
            else:
                raise IntegrityError
        except:
            raise IntegrityError


    def revoke(self, user, name):
        try:
            pointer_id = self.crypto.message_authentication_code(name, self.permanent_filename_key, hash_name='SHA256')
            file_value = self.download(name)
            new_file_id = self.crypto.get_random_bytes(16)
            new_file_pointer = self.username + "/data/" + new_file_id
            new_file_encryption_key = self.crypto.get_random_bytes(16)
            new_file_mac_key = self.crypto.get_random_bytes(16)
            new_file_info = new_file_pointer + new_file_encryption_key + new_file_mac_key
            new_encrypted_file_info = self.encrypt_then_mac(self.permanent_encryption_key, self.permanent_mac_key,
                                                            new_file_info)
            new_final_file_info = new_encrypted_file_info + self.crypto.message_authentication_code(new_encrypted_file_info + name,
                                                                                                    self.permanent_filename_key,
                                                                                                    hash_name='SHA256')
            new_encrypted_file = self.encrypt_then_mac(new_file_encryption_key, new_file_mac_key, file_value)
            self.storage_server.put(self.username + "/keys/" + pointer_id, "[POINTER]" + new_final_file_info)
            self.storage_server.put(new_file_pointer, "[DATA]" + new_encrypted_file)
            if not self.storage_server.get(self.username + "/children_of/" + pointer_id) is None:
                children_dict = json.loads(self.check_then_decrypt(self.permanent_encryption_key, self.permanent_mac_key,
                                                                   self.storage_server.get(self.username + "/children_of/" + pointer_id)))
                for child in children_dict:
                    if (child != user):
                        share_node_id = children_dict[child][:32]
                        share_node_encryption_key = children_dict[child][32:64]
                        share_node_mac_key = children_dict[child][64:]
                        new_share_node_content = new_file_pointer + new_file_encryption_key + new_file_mac_key
                        new_encrypted_share_node_content = self.encrypt_then_mac(share_node_encryption_key,
                                                                                 share_node_mac_key, new_share_node_content)
                        self.storage_server.put(share_node_id, "[POINTER]" + new_encrypted_share_node_content)
        except:
            raise IntegrityError
