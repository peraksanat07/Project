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
    UPLOAD_FOLDER = '/Users/peraksana/Downloads/Project/static/images/'  # Folder where images will be stored
    AUTHOR_FOLDER = '/static/images/author'
    BOOK_FOLDER = '/static/images/book'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Max file size: 16MB