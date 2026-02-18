"""File handling utilities for uploads and storage."""

import os
import hashlib
import logging
import mimetypes
from typing import Dict, Optional, Tuple
from datetime import datetime
import aiofiles

logger = logging.getLogger(__name__)


class FileHandler:
    """Handle file uploads, storage, and S3 operations."""

    # Allowed file extensions for analysis
    ALLOWED_EXTENSIONS = {
        # Scripts
        '.ps1', '.psm1', '.psd1',  # PowerShell
        '.js', '.mjs',  # JavaScript
        '.vbs', '.vbe', '.wsf', '.wsh',  # VBScript
        '.bat', '.cmd',  # Batch
        '.py', '.pyw',  # Python
        '.sh', '.bash',  # Bash
        '.hta',  # HTML Application
        '.php',  # PHP

        # Documents
        '.doc', '.docx', '.docm',
        '.xls', '.xlsx', '.xlsm',
        '.ppt', '.pptx', '.pptm',
        '.pdf',
        '.rtf',

        # Executables (for hash analysis)
        '.exe', '.dll', '.scr', '.sys',
        '.msi', '.msp',

        # Archives
        '.zip', '.rar', '.7z', '.tar', '.gz',

        # Other
        '.lnk',  # Shortcuts
        '.iso', '.img',  # Disk images
        '.json', '.xml', '.html', '.htm',  # Data files
    }

    # Maximum file sizes by type (in bytes)
    MAX_SIZES = {
        'script': 10 * 1024 * 1024,  # 10MB for scripts
        'document': 50 * 1024 * 1024,  # 50MB for documents
        'executable': 100 * 1024 * 1024,  # 100MB for executables
        'archive': 100 * 1024 * 1024,  # 100MB for archives
        'default': 50 * 1024 * 1024,  # 50MB default
    }

    def __init__(self, upload_dir: str = "./uploads"):
        """
        Initialize file handler.

        Args:
            upload_dir: Directory for file uploads
        """
        self.upload_dir = upload_dir
        os.makedirs(upload_dir, exist_ok=True)

    def get_file_type_category(self, filename: str) -> str:
        """Get the category of a file based on extension."""
        ext = os.path.splitext(filename.lower())[1]

        script_exts = {'.ps1', '.psm1', '.js', '.vbs', '.vbe', '.bat', '.cmd', '.py', '.sh', '.hta', '.php'}
        doc_exts = {'.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm', '.pdf', '.rtf'}
        exe_exts = {'.exe', '.dll', '.scr', '.sys', '.msi'}
        archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz'}

        if ext in script_exts:
            return 'script'
        elif ext in doc_exts:
            return 'document'
        elif ext in exe_exts:
            return 'executable'
        elif ext in archive_exts:
            return 'archive'
        return 'default'

    def is_allowed_file(self, filename: str) -> bool:
        """Check if file extension is allowed."""
        ext = os.path.splitext(filename.lower())[1]
        return ext in self.ALLOWED_EXTENSIONS

    def get_max_size(self, filename: str) -> int:
        """Get maximum allowed size for a file type."""
        category = self.get_file_type_category(filename)
        return self.MAX_SIZES.get(category, self.MAX_SIZES['default'])

    @staticmethod
    def calculate_hashes(content: bytes) -> Dict[str, str]:
        """
        Calculate multiple hashes for file content.

        Args:
            content: File content as bytes

        Returns:
            Dictionary with md5, sha1, and sha256 hashes
        """
        return {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest()
        }

    async def save_file(self, content: bytes, filename: str) -> Tuple[str, Dict[str, str]]:
        """
        Save file to upload directory.

        Args:
            content: File content
            filename: Original filename

        Returns:
            Tuple of (saved_path, hashes)
        """
        hashes = self.calculate_hashes(content)

        # Create safe filename with hash prefix
        safe_filename = f"{hashes['sha256']}_{self._sanitize_filename(filename)}"
        file_path = os.path.join(self.upload_dir, safe_filename)

        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(content)

        return file_path, hashes

    async def read_file(self, file_path: str) -> bytes:
        """
        Read file content.

        Args:
            file_path: Path to file

        Returns:
            File content as bytes
        """
        async with aiofiles.open(file_path, 'rb') as f:
            return await f.read()

    async def read_file_text(self, file_path: str, encoding: str = 'utf-8') -> str:
        """
        Read file as text.

        Args:
            file_path: Path to file
            encoding: Text encoding

        Returns:
            File content as string
        """
        async with aiofiles.open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            return await f.read()

    async def delete_file(self, file_path: str) -> bool:
        """
        Delete a file.

        Args:
            file_path: Path to file

        Returns:
            True if deleted, False otherwise
        """
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                return True
            return False
        except Exception:
            return False

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues."""
        # Remove path components
        filename = os.path.basename(filename)
        # Replace potentially dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*', '\x00']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        # Limit length
        if len(filename) > 200:
            name, ext = os.path.splitext(filename)
            filename = name[:200-len(ext)] + ext
        return filename

    def detect_file_type(self, content: bytes, filename: str) -> Dict[str, str]:
        """
        Detect file type using magic bytes and extension.

        Args:
            content: File content
            filename: Filename for extension check

        Returns:
            Dictionary with file type information
        """
        result = {
            'extension': os.path.splitext(filename.lower())[1],
            'mime_type': None,
            'magic_type': None,
            'category': self.get_file_type_category(filename)
        }

        # Get MIME type from extension
        mime_type, _ = mimetypes.guess_type(filename)
        result['mime_type'] = mime_type

        # Try to detect using magic bytes
        try:
            import magic
            result['magic_type'] = magic.from_buffer(content[:2048])
        except ImportError:
            logger.debug("python-magic not available, skipping magic byte detection")
        except Exception:
            logger.warning("Failed to detect file type using magic bytes", exc_info=True)

        return result


class S3Handler:
    """Handle S3 storage operations."""

    def __init__(self, bucket_name: Optional[str] = None):
        """
        Initialize S3 handler.

        Args:
            bucket_name: S3 bucket name
        """
        from config import get_settings
        settings = get_settings()

        self.bucket_name = bucket_name or settings.s3_bucket_name
        self.region = settings.aws_region

        # Initialize boto3 client lazily
        self._client = None

    @property
    def client(self):
        """Get or create S3 client."""
        if self._client is None:
            import boto3
            from config import get_settings
            settings = get_settings()

            self._client = boto3.client(
                's3',
                region_name=self.region,
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key
            )
        return self._client

    async def upload_file(self, file_path: str, s3_key: str,
                         content_type: Optional[str] = None) -> Dict:
        """
        Upload a file to S3.

        Args:
            file_path: Local file path
            s3_key: S3 object key
            content_type: MIME type

        Returns:
            Dictionary with upload result
        """
        import asyncio

        try:
            extra_args = {}
            if content_type:
                extra_args['ContentType'] = content_type

            # Run in thread pool since boto3 is synchronous
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.upload_file(
                    file_path, self.bucket_name, s3_key,
                    ExtraArgs=extra_args if extra_args else None
                )
            )

            return {
                'success': True,
                'bucket': self.bucket_name,
                'key': s3_key,
                'url': f"s3://{self.bucket_name}/{s3_key}"
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def download_file(self, s3_key: str, local_path: str) -> Dict:
        """
        Download a file from S3.

        Args:
            s3_key: S3 object key
            local_path: Local path to save file

        Returns:
            Dictionary with download result
        """
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.download_file(
                    self.bucket_name, s3_key, local_path
                )
            )

            return {'success': True, 'path': local_path}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def delete_file(self, s3_key: str) -> Dict:
        """
        Delete a file from S3.

        Args:
            s3_key: S3 object key

        Returns:
            Dictionary with deletion result
        """
        import asyncio

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.client.delete_object(
                    Bucket=self.bucket_name, Key=s3_key
                )
            )

            return {'success': True}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def get_presigned_url(self, s3_key: str, expiration: int = 3600) -> Dict:
        """
        Generate a presigned URL for file access.

        Args:
            s3_key: S3 object key
            expiration: URL expiration in seconds

        Returns:
            Dictionary with presigned URL
        """
        try:
            url = self.client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': s3_key},
                ExpiresIn=expiration
            )

            return {'success': True, 'url': url, 'expires_in': expiration}

        except Exception as e:
            return {'success': False, 'error': str(e)}
