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
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        self.permanent_encryption_key = self.get_permanent_keys()[:32]
        self.permanent_mac_key = self.get_permanent_keys()[32:]

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
        permanent_keys = permanent_encryption_key + permanent_mac_key
        encrypted_permanent_keys = self.crypto.asymmetric_encrypt(permanent_keys, self.elg_priv_key)
        signature_permanent_keys = self.crypto.asymmetric_sign(encrypted_permanent_keys, self.rsa_priv_key)
        self.storage_server.put(self.username + '/permanent_keys/keys', encrypted_permanent_keys)
        self.storage_server.put(self.username + '/permanent_keys/signature', signature_permanent_keys)
        return permanent_keys

    def retrieve_file_dictionary(self):
        encrypted_dict_string = self.storage_server.get(self.username + '/file_dictionary')
        if encrypted_dict_string is None:
            return None
        else:
            dict_string = self.check_then_decrypt(self.permanent_encryption_key, self.permanent_mac_key,
                                              self.storage_server.get(self.username + '/file_dictionary'),)
            return json.loads(dict_string)

    def update_file_dict(self, filename, file_info):
        new_file_dict = self.retrieve_file_dictionary()
        if new_file_dict is None:
            new_file_dict = {filename : file_info}
        else:
            new_file_dict[filename] = file_info
            self.storage_server.delete(self.username + '/file_dictionary')
        self.storage_server.put(self.username + '/file_dictionary',
                                self.encrypt_then_mac(self.permanent_encryption_key, self.permanent_mac_key,
                                                      json.dumps(new_file_dict)))

    def upload(self, name, value):
        # Replace with your implementation
        try:
            file_id = self.crypto.get_random_bytes(16)
            file_encryption_key = self.crypto.get_random_bytes(16)
            file_mac_key = self.crypto.get_random_bytes(16)
            file_info = file_id + file_encryption_key + file_mac_key
            self.update_file_dict(name, file_info)
            encrypted_file = self.encrypt_then_mac(file_encryption_key, file_mac_key, value)
            self.storage_server.put(self.username + '/files/' + file_id, encrypted_file)
        except:
            raise IntegrityError

    def download(self, name):
        # Replace with your implementation
        try:
            file_dict = self.retrieve_file_dictionary()
            if file_dict is None:
                file_dict = {}
            file_id = file_dict[name][:32]
            file_encryption_key = file_dict[name][32:64]
            file_mac_key = file_dict[name][64:]
            encrypted_file = self.storage_server.get(self.username + '/files/' + file_id)
            return self.check_then_decrypt(file_encryption_key, file_mac_key, encrypted_file)
        except KeyError:
            return None
        except:
            raise IntegrityError

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

