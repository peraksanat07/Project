from datetime import timedelta
import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    TITLE = 'Library'
    DATABASE = 'project.db'
    DEBUG = True

    # MySQL Configuration
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'root'
    MYSQL_PASSWORD = ''
    MYSQL_DB = 'user-system'

# File Upload Configuration
# Existing config values
    UPLOAD_FOLDER = os.path.join(basedir, 'app', 'static', 'images')

    # New paths for author and book images
    AUTHOR_IMAGE_FOLDER = os.path.join(UPLOAD_FOLDER, 'author')
    BOOK_IMAGE_FOLDER = os.path.join(UPLOAD_FOLDER, 'book')

    # Ensure directories exist
    os.makedirs(AUTHOR_IMAGE_FOLDER, exist_ok=True)
    os.makedirs(BOOK_IMAGE_FOLDER, exist_ok=True)
    # Folder where images will be stored
    AUTHOR_FOLDER = '/static/images/author'
    BOOK_FOLDER = '/static/images/book'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Max file size: 16MB

    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
