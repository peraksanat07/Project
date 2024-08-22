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
    UPLOAD_FOLDER = 'static/uploads/'  # Folder where images will be stored
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Max file size: 16MB