import unittest
from unittest.mock import patch, MagicMock
from services import file_service
from utils.dataclasses import FileInfo, PAC
import base64

class TestFileService(unittest.TestCase):
    def setUp(self):
        self.user = MagicMock()
        self.user.uuid = 'user-uuid'
        self.master_key = b'0' * 32
        self.private_key = b'1' * 32
        self.file_info = MagicMock(spec=FileInfo)
        self.file_info.file_uuid = 'file-uuid'
        self.file_info.k_file_nonce = b'nonce'
        self.file_info.k_file_encrypted = b'encrypted'
        self.file_info.name = 'test.txt'
        self.file_info.mime_type = 'text/plain'

    @patch('services.file_service.server')
    @patch('services.file_service.CryptoUtils')
    def test_upload_file_service_success(self, mock_crypto, mock_server):
        file_storage = MagicMock()
        file_storage.read.return_value = b'data'
        file_storage.filename = 'test.txt'
        mock_crypto.encrypt_with_key.side_effect = [
            (b'nonce', b'ciphertext'),
            (b'k_file_nonce', b'enc_k_file')
        ]
        mock_server.upload_file.return_value = {'file_uuid': 'uuid', 'success': True}
        result = file_service.upload_file_service(file_storage, self.user, self.master_key)
        self.assertEqual(result, 'uuid')

    @patch('services.file_service.server')
    @patch('services.file_service.CryptoUtils')
    def test_upload_file_service_failure(self, mock_crypto, mock_server):
        file_storage = MagicMock()
        file_storage.read.return_value = b'data'
        file_storage.filename = 'test.txt'
        mock_crypto.encrypt_with_key.side_effect = [
            (b'nonce', b'ciphertext'),
            (b'k_file_nonce', b'enc_k_file')
        ]
        mock_server.upload_file.return_value = {'success': False, 'error': 'fail'}
        with self.assertRaises(Exception):
            file_service.upload_file_service(file_storage, self.user, self.master_key)

    @patch('services.file_service.server')
    @patch('services.file_service.CryptoUtils')
    @patch('services.file_service.get_user_ed25519_private_key')
    @patch('services.file_service.load_x25519_public_key')
    def test_share_file_with_user_service_success(self, mock_load_key, mock_get_priv, mock_crypto, mock_server):
        user_to_share = MagicMock()
        user_to_share.uuid = 'recipient-uuid'
        mock_server.get_user_by_name.return_value = user_to_share
        mock_crypto.decrypt_with_key.return_value = b'k_file'
        mock_server.get_user_keys.return_value = {
            'identity_key_public': 'aWQ=',
            'signed_prekey_public': 'c2lnbmVk'
        }
        mock_load_key.return_value = MagicMock()
        mock_crypto.perform_3xdh_sender.return_value = b'shared_key'
        mock_crypto.encrypt_with_key.return_value = (b'nonce', b'enc_k_file')
        mock_crypto.create_pac.return_value = MagicMock(to_dict=lambda: {'pac': 'data'})
        mock_server.send_pac.return_value = None
        result = file_service.share_file_with_user_service(self.file_info, 'recipient', self.user, self.master_key)
        self.assertEqual(result[1], user_to_share)

    @patch('services.file_service.db')
    def test_delete_file_from_storage_and_db(self, mock_db):
        file = MagicMock()
        file_service.delete_file_(file)
        mock_db.session.delete.assert_called_once_with(file)
        mock_db.session.commit.assert_called_once()

    @patch('services.file_service.server')
    @patch('services.file_service.PAC')
    def test_refresh_pacs_service(self, mock_pac, mock_server):
        mock_server.get_user_pacs.return_value = {
            'received_pacs': [{'a': 1}],
            'issued_pacs': [{'b': 2}]
        }
        mock_pac.from_json.side_effect = lambda x: x
        received, issued = file_service.refresh_pacs_service(self.user, self.private_key)
        self.assertEqual(received, [{'a': 1}])
        self.assertEqual(issued, [{'b': 2}])

    @patch('services.file_service.server')
    @patch('services.file_service.FileInfo')
    def test_refresh_owned_file_service(self, mock_fileinfo, mock_server):
        mock_server.get_owned_files.return_value = [{'id': 1}]
        mock_fileinfo.from_dict.side_effect = lambda x: x
        result = file_service.refresh_owned_file_service(self.user, self.private_key)
        self.assertEqual(result, [{'id': 1}])

    @patch('services.file_service.session_manager')
    @patch('services.file_service.refresh_owned_file_service')
    @patch('services.file_service.refresh_pacs_service')
    def test_refresh_all_files_service(self, mock_refresh_pacs, mock_refresh_owned, mock_session):
        mock_refresh_owned.return_value = [MagicMock(to_dict=lambda: {'f': 1})]
        mock_refresh_pacs.return_value = ([MagicMock(to_dict=lambda: {'p': 2})], [MagicMock(to_dict=lambda: {'q': 3})])
        owned, received, issued = file_service.refresh_all_files_service(self.user, self.private_key)
        self.assertTrue(mock_session.set_session_value.called)
        self.assertEqual(len(owned), 1)
        self.assertEqual(len(received), 1)
        self.assertEqual(len(issued), 1)

    @patch('services.file_service.server')
    @patch('services.file_service.CryptoUtils')
    @patch('services.file_service.get_user_x25519_private_keys')
    @patch('services.file_service.load_x25519_public_key')
    @patch('services.file_service.ed25519')
    def test_download_file_service_success(self, mock_ed25519, mock_load_key, mock_get_priv, mock_crypto, mock_server):
        pac = MagicMock()
        pac.file_uuid = 'file-uuid'
        pac.issuer_id = 'issuer-uuid'
        pac.sender_ephemeral_public = base64.b64encode(b'ephemeral').decode()
        pac.k_file_nonce = b'nonce'
        pac.encrypted_file_key = b'encrypted'
        pac.filename = 'test.txt'
        pac.mime_type = 'text/plain'
        pac.to_dict.return_value = {'pac': 'data'}
        pacs = [pac]
        mock_server.get_user_keys.return_value = {'identity_key_public': base64.b64encode(b'pub').decode()}
        mock_ed25519.Ed25519PublicKey.from_public_bytes.return_value = MagicMock()
        mock_crypto.verify_pac.return_value = True
        mock_load_key.return_value = MagicMock()
        mock_get_priv.return_value = (MagicMock(), MagicMock())
        mock_crypto.perform_3xdh_recipient.return_value = b'shared_key'
        mock_crypto.decrypt_with_key.side_effect = [b'k_file', b'data']
        mock_server.download_file.return_value = {
            'ciphertext': base64.b64encode(b'data').decode(),
            'file_nonce': b'nonce',
            'filename': 'test.txt',
            'mime_type': 'text/plain'
        }
        result = file_service.download_file_service('file-uuid', pacs, self.user, self.master_key)
        self.assertEqual(result[1], 'test.txt')
        self.assertEqual(result[2], 'text/plain')

    @patch('services.file_service.server')
    @patch('services.file_service.CryptoUtils')
    def test_download_file_service_file_not_found(self, mock_crypto, mock_server):
        pacs = []
        with self.assertRaises(file_service.FileDownloadError):
            file_service.download_file_service('file-uuid', pacs, self.user, self.master_key)

if __name__ == '__main__':
    unittest.main()
