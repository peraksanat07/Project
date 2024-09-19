# Import necessary modules and classes from Flask and other libraries
from flask import Flask, render_template, request, session, redirect, url_for
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from config import Config
from flask_bcrypt import Bcrypt
import sqlite3
import re

# Create an instance of the Flask class
app = Flask(__name__)
bcrypt = Bcrypt(app)
# Load configuration settings from Config object
app.config.from_object(Config)
# Set a secret key for session management
app.secret_key = "testing secret thing"

MAX_INPUT_LENGTH = 50


@app.before_request
def make_session_permanent():
    session.permanent = True


@app.before_request
def enforce_https():
    if not request.is_secure and not app.debug:
        return redirect(request.url.replace("http://", "https://"))


def ensure_logged_in_or_error():
    if 'userid' not in session:
        return render_template('error.html')


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in \
        app.config['ALLOWED_EXTENSIONS']


def is_valid_id(id):
    # SQLite INTEGER range
    MIN_INTEGER = -9223372036854775808
    MAX_INTEGER = 9223372036854775807
    return MIN_INTEGER <= id <= MAX_INTEGER


# Helper function to interact with the database
def query_db(query, args=(), one=False):
    # Connect to the database using the path specified in the config
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute(query, args)
    # Fetch all results from the query
    answer = cur.fetchall()
    cur.close()
    con.close()
    # Return the first result if 'one' is True, otherwise return all results
    return (answer[0] if answer else None) if one else answer


def truncate_text(text, max_length=MAX_INPUT_LENGTH):
    if len(text) > max_length:
        return text[:max_length] + '...'
    return text


@app.context_processor
def context_processor():
    # Add a global 'title' variable accessible in all templates
    return dict(title=app.config['TITLE'])


# Route for the homepage
@app.route('/')
def homepage():
    return render_template("home.html")


# Route for searching content, handles both GET and POST requests
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        # Retrieve the search term from the submitted form
        search_term = request.form.get('searchterm')

        # Check if the search term is empty
        if not search_term:
            # Return the search page with empty results
            return render_template('search.html',
                                   search_term='',
                                   books=[],
                                   genres=[],
                                   authors=[])
        print(f"Search term: {search_term}")
        truncated_term = truncate_text(search_term,
                                       max_length=MAX_INPUT_LENGTH)
        # Define SQL queries for searching Books, Genre, and Author tables
        search_queries = [
            ("SELECT id, name, blurb FROM Books WHERE name LIKE ?", '%' +
             search_term + '%'),
            ("SELECT id, name, description FROM Genre WHERE name LIKE ?",
             '%' + search_term + '%'),
            ("SELECT id, name, description FROM Author WHERE name LIKE ?",
             '%' + search_term + '%')
        ]
        # Execute each query and store the results
        results = [query_db(query, (param,)) for query, param in
                   search_queries]
        # Render the 'search.html' template with search results
        return render_template('search.html',
                               search_term=truncated_term,
                               books=results[0], genres=results[1],
                               authors=results[2])
    return render_template("error.html"), 404


# Route for listing all authors
@app.route('/author')
def author():
    # Query the database for all authors
    authors = query_db("SELECT id, name, image FROM Author ORDER BY id")
    # Render the 'author.html' template with the list of authors
    return render_template("author.html", authors=authors)


# Route for displaying details of a specific author
@app.route('/author/<int:id>')
def author_details(id):
    if not is_valid_id(id):
        return render_template("error.html"), 400

    try:
        # Query the database for the author with the specified ID
        author = query_db("SELECT * FROM Author WHERE id=?", (id,), one=True)
        if author:
            # Query the database for books associated with the author
            books = query_db("SELECT id, name FROM Books WHERE id IN \
                            (SELECT book FROM book_author WHERE author=?)", (id,))
            # Render the 'a_details.html' template with author and book details
            return render_template("a_details.html", author=author,
                                   books=books)
        # Render 'error.html' if author is not found
        return render_template("error.html"), 404
    except sqlite3.OperationalError:
        # Handle case where the id is too large for SQLite
        return render_template("error.html"), 400


# Route for listing all books
@app.route('/books')
def books():
    # Query the database for all books
    books = query_db("SELECT id, name, image FROM Books ORDER BY id")
    # Render the 'book.html' template with the list of books
    return render_template("book.html", books=books)


# Route for displaying details of a specific book
@app.route('/books/<int:id>')
def book_details(id):
    # Check if id is valid
    if not is_valid_id(id):
        return render_template("error.html"), 400

    try:
        # Query the database for the book with the specified ID
        book = query_db("SELECT * FROM Books WHERE id=?", (id,), one=True)
        if book:
            # Query the database for genres associated with the book
            genre = query_db("SELECT id, name FROM Genre WHERE id IN \
                             (SELECT genre FROM book_genre WHERE book=?)",
                             (id,))
            # Query the database for authors associated with the book
            authors = query_db("SELECT id, name FROM Author WHERE id IN \
                               (SELECT author FROM book_author WHERE book=?)",
                               (id,))
    # Render the 'b_details.html' template with book, genre, and author details
            return render_template("b_details.html",
                                   book=book,
                                   genre=genre,
                                   authors=authors)
        # Render 'error.html' if book is not found
        return render_template("error.html"), 404
    except sqlite3.OperationalError:
        # Handle case where the id is too large for SQLite
        return render_template("error.html"), 400


# Route for listing all genres
@app.route('/genre')
def genre():
    # Query the database for all genres
    genres = query_db("SELECT id, name FROM Genre ORDER BY id")
    # Render the 'genre.html' template with the list of genres
    return render_template("genre.html", genres=genres)


# Route for displaying details of a specific genre
@app.route('/genre/<int:id>')
def genre_details(id):
    # Check if id is valid
    if not is_valid_id(id):
        return render_template("error.html"), 400  # Bad Request

    try:
        # Query the database for the genre with the specified ID
        genre = query_db("SELECT * FROM Genre WHERE id=?", (id,), one=True)
        if genre:
            # Render the 'g_details.html' template with genre details
            return render_template("g_details.html", genre=genre)
        # Render 'error.html' if genre is not found
        return render_template("error.html"), 404
    except sqlite3.OperationalError:
        # Handle case where the id is too large for SQLite
        return render_template("error.html"), 400  # Bad Request


# Route for the Login page
@app.route('/log-in', methods=['GET', 'POST'])
def log_in():
    message = ''
    if request.method == 'POST' and all(k in request.form for k in
                                        ('username', 'password')):
        # Retrieve username and password from the form
        username, password = request.form['username'], request.form['password']
        user_password = query_db('SELECT Password FROM users \
                                 WHERE Username = ?', (username,), one=True)
        if user_password is None:
            # Username not found in the database
            message = 'Username not found. Please try again!'
        else:
            user = bcrypt.check_password_hash(user_password[0].encode('utf-8'),
                                              password)
        # Query the database for user with the provided username and password
            if user:
                # Set session variables for the logged-in user
                user_details = query_db('SELECT * FROM users WHERE \
                                        Username = ?', (username,), one=True)
                session.update({'loggedin': True, 'userid': user_details[0],
                                'name': user_details[1],
                                'email': user_details[2],
                                'age': user_details[3]})
                message = 'Logged in successfully!'
                return redirect(url_for('admin'))  # Redirect to admin page
            message = 'Please enter correct password!'
    return render_template('login.html', message=message)


# Route for logging out
@app.route('/logout')
def logout():
    # Remove user data from the session
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    # Redirect to the login page
    return redirect(url_for('log_in'))


# Error handler for 404 errors
@app.errorhandler(404)
def page_not_found(e):
    # Render the 'error.html' template with a 404 status code
    return render_template('error.html'), 404


# Route for the Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    username = ''
    email = ''
    age = ''
    if request.method == 'POST' and 'username' in request.form and\
        'password' in request.form and 'email' in request.form and\
            'age' in request.form:
        # Retrieve form data
        username = request.form['username']
        password = request.form['password']
        confirmpassword = request.form['confirmpassword']
        email = request.form['email']

        try:
            # Validate age input
            age = int(request.form['age'])
        except ValueError:
            message = 'Age must be a number!'
            return render_template('register.html', message=message,
                                   username=username, email=email, age=age)
        con = sqlite3.connect('project.db')
        cursor = con.cursor()
        # Check if an account with the provided email already exists
        account = query_db('SELECT * FROM users WHERE Email = ?', (email,),
                           one=True)
        if account:
            message = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Invalid email address!'
        elif age < 16:
            message = 'You are not old enough to register'
        elif not username or not password or not email or not age:
            message = 'Please fill out the form!'
        elif password != confirmpassword:
            message = 'Passwords do not match!'
        else:
            # Insert new user into the database
            enc_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute('INSERT INTO users(Username, Email, Password, Age)\
                            VALUES(?, ?, ?, ?)', (username, email,
                                                  enc_password, age,))
            con.commit()
            con.close()
            return redirect(url_for('log_in'))
    elif request.method == 'POST':
        message = 'Please fill out the form!'
    # Render the 'register.html' template with a message and form data
    return render_template('register.html', message=message,
                           username=username, email=email, age=age)


@app.route('/password', methods=['GET', 'POST'])
def password():
    message = ''
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmpassword')

        if not email or not password or not confirm_password:
            message = 'Please fill out the form!'
            return render_template("password.html", message=message)

        if password != confirm_password:
            message = 'Passwords do not match!'
            return render_template("password.html", message=message)

        # Validate email format
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Invalid email address!'
            return render_template("password.html", message=message)

        # Connect to the database and check if the user exists
        con = sqlite3.connect(app.config['DATABASE'])
        cursor = con.cursor()
        user = query_db('SELECT * FROM users WHERE Email = ?', (email,),
                        one=True)
        if user:
            # Hash the new password
            hashed_password = generate_password_hash(password)
            cursor.execute('UPDATE users SET Password = ? WHERE Email = ?',
                           (hashed_password, email))
            con.commit()
            message = 'Password updated successfully!'
        else:
            message = 'User not found'
        con.close()

    return render_template("password.html", message=message)


# Route for the Welcome page (admin dashboard)
@app.route('/admin')
def admin():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    if 'name' in session and 'email' in session and 'age' in session:
        name = session.get("name")
        email = session['email']
        age = session['age']

        # Fetch data for books, genres, and authors
        search_queries = [
            ("SELECT id, name, blurb FROM Books", ()),
            ("SELECT id, name, description FROM Genre", ()),
            ("SELECT id, name, description FROM Author", ())
        ]

        results = [query_db(query, param) for query, param in search_queries]

        return render_template('admin.html', name=name, email=email, age=age,
                               books=results[0], genres=results[1], authors=results[2])


@app.after_request
def add_cache_control_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, \
                                        post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@app.route('/edit', methods=['GET', 'POST'])
def edit():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    message = ''
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        age = request.form['age']
        password = request.form['password']
        confirm_password = request.form['confirmpassword']

        # Validate form data (e.g., check if passwords match)
        if password != confirm_password:
            message = 'Passwords do not match!'
            return render_template('edit.html', message=message)

        user_id = session.get('userid')

        if user_id:
            # Connect to the database
            con = sqlite3.connect(app.config['DATABASE'])
            cursor = con.cursor()

            # Check if the new username or email is already taken
            cursor.execute("SELECT id FROM users WHERE (Username = ? OR Email = ?) AND id != ?", 
                           (username, email, user_id))
            existing_user = cursor.fetchone()

            if existing_user:
                message = 'Username or email already in use!'
                con.close()
                return render_template('edit.html', message=message)

            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Update the user's information
            cursor.execute("UPDATE users SET Username = ?, Email = ?, Age = ?, Password = ? WHERE id = ?",
                           (username, email, age, hashed_password, user_id))
            con.commit()
            con.close()

            message = 'Profile updated successfully!'
        else:
            message = 'User not logged in.'
            return redirect(url_for('log_in'))

    return render_template('edit.html', message=message)


@app.route('/delete_account', methods=['POST'])
def delete_account():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result

    user_id = session.get('userid')

    if user_id:
        # Connect to the database
        con = sqlite3.connect(app.config['DATABASE'])
        cursor = con.cursor()

        # Delete the user's account
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        con.commit()
        con.close()

        # Log the user out
        session.pop('userid', None)

        return redirect(url_for('log_in'))

    return redirect(url_for('edit'))


@app.route('/add_database', methods=['GET', 'POST'])
def add_database():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    message1 = ''
    message2 = ''
    message3 = ''
    # Handle author submission
    if 'aname' in request.form and 'a_description' in request.form:
        aname = request.form.get('aname')
        a_description = request.form.get('a_description')
        if 'a_image' not in request.files:
            message1 += 'No file part'
        file = request.files['a_image']
        if file.filename == '':
            message1 += 'No selected file'
        if file and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                                   'author', image_filename))
        if aname and a_description and image_filename:
            con = sqlite3.connect(app.config['DATABASE'])
            cursor = con.cursor()
            cursor.execute('INSERT INTO Author (name, description, image) \
                           VALUES (?, ?, ?)', (aname, a_description,
                                               os.path.join(app.config
                                                            ['AUTHOR_FOLDER'],
                                                            image_filename)))
            con.commit()
            con.close()
            message1 += ' Author added successfully!'

        # Handle book submission
    elif 'bname' in request.form and 'blurb' in request.form:
        bname = request.form.get('bname')
        blurb = request.form.get('blurb')
        if 'b_image' not in request.files:
            message2 += 'No file part'
        file = request.files['b_image']
        if file.filename == '':
            message2 += 'No selected file'
        if file and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                                   'book', image_filename))
        if bname and blurb and image_filename:
            con = sqlite3.connect(app.config['DATABASE'])
            cursor = con.cursor()
            cursor.execute('INSERT INTO Books (name, blurb, image) \
                           VALUES (?, ?, ?)', (bname, blurb,
                                               os.path.join(app.config
                                                            ['BOOK_FOLDER'],
                                                            image_filename)))
            con.commit()
            con.close()
            message2 += ' Book added successfully!'

        # Handle genre submission
    elif 'gname' in request.form and 'g_description' in request.form:
        gname = request.form.get('gname')
        g_description = request.form.get('g_description')
        if gname and g_description:
            con = sqlite3.connect(app.config['DATABASE'])
            cursor = con.cursor()
            cursor.execute('INSERT INTO Genre (name, description) \
                           VALUES (?, ?)', (gname, g_description))
            con.commit()
            con.close()
            message3 += ' Genre added successfully!'

    return render_template('add_db.html',
                           message1=message1,
                           message2=message2,
                           message3=message3)


@app.route('/delete_database', methods=['GET', 'POST'])
def delete_database():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    message1 = ''
    message2 = ''
    message3 = ''
    if request.method == 'POST':
        if 'a_id' in request.form:
            a_id = request.form.get('a_id')
            if a_id:
                con = sqlite3.connect(app.config['DATABASE'])
                cursor = con.cursor()
                cursor.execute('DELETE FROM Author WHERE id=?', (a_id,))
                con.commit()
                con.close()
                message1 = 'Author deleted successfully!'
            else:
                message1 = 'No ID provided for Author!'

        elif 'b_id' in request.form:
            b_id = request.form.get('b_id')
            if b_id:
                con = sqlite3.connect(app.config['DATABASE'])
                cursor = con.cursor()
                cursor.execute('DELETE FROM Books WHERE id=?', (b_id,))
                con.commit()
                con.close()
                message2 = 'Book deleted successfully!'
            else:
                message2 = 'No ID provided for Book!'

        elif 'g_id' in request.form:
            g_id = request.form.get('g_id')
            if g_id:
                con = sqlite3.connect(app.config['DATABASE'])
                cursor = con.cursor()
                cursor.execute('DELETE FROM Genre WHERE id=?', (g_id,))
                con.commit()
                con.close()
                message3 = 'Genre deleted successfully!'
            else:
                message3 = 'No ID provided for Genre!'
    # Render the 'admin.html' template
    return render_template("delete_db.html",
                           message1=message1,
                           message2=message2,
                           message3=message3)


@app.route('/change_database',  methods=['GET', 'POST'])
def change_database():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    message1 = ''
    message2 = ''
    message3 = ''

    # Handle author update
    if 'a_id' in request.form and 'aname' in request.form and 'a_description' in request.form:
        a_id = request.form.get('a_id')
        aname = request.form.get('aname')
        a_description = request.form.get('a_description')

        # Optional image update
        if 'a_image' in request.files and request.files['a_image'].filename != '':
            file = request.files['a_image']
            if allowed_file(file.filename):
                image_filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'author',
                                       image_filename))
                image_path = os.path.join(app.config['AUTHOR_FOLDER'],
                                          image_filename)
                # Update with new image
                con = sqlite3.connect(app.config['DATABASE'])
                cursor = con.cursor()
                cursor.execute('UPDATE Author SET name=?, description=?, image=? WHERE id=?',
                               (aname, a_description, image_path, a_id))
                con.commit()
                con.close()
                message1 = 'Author updated successfully!'
            else:
                message1 = 'Invalid file type for Author image!'
        else:
            # Update without image
            con = sqlite3.connect(app.config['DATABASE'])
            cursor = con.cursor()
            cursor.execute('UPDATE Author SET name=?, description=? WHERE id=?',
                           (aname, a_description, a_id))
            con.commit()
            con.close()
            message1 = 'Author updated successfully without new image!'

    # Handle book update
    elif 'b_id' in request.form and 'bname' in request.form and 'blurb' in request.form:
        b_id = request.form.get('b_id')
        bname = request.form.get('bname')
        blurb = request.form.get('blurb')

        # Optional image update
        if 'b_image' in request.files and request.files['b_image'].filename != '':
            file = request.files['b_image']
            if allowed_file(file.filename):
                image_filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'book', image_filename))
                image_path = os.path.join(app.config['BOOK_FOLDER'], image_filename)
                # Update with new image
                con = sqlite3.connect(app.config['DATABASE'])
                cursor = con.cursor()
                cursor.execute('UPDATE Books SET name=?, blurb=?, image=? WHERE id=?',
                               (bname, blurb, image_path, b_id))
                con.commit()
                con.close()
                message2 = 'Book updated successfully!'
            else:
                message2 = 'Invalid file type for Book image!'
        else:
            # Update without image
            con = sqlite3.connect(app.config['DATABASE'])
            cursor = con.cursor()
            cursor.execute('UPDATE Books SET name=?, blurb=? WHERE id=?',
                           (bname, blurb, b_id))
            con.commit()
            con.close()
            message2 = 'Book updated successfully without new image!'

    # Handle genre update
    elif 'g_id' in request.form and 'gname' in request.form and 'g_description' in request.form:
        g_id = request.form.get('g_id')
        gname = request.form.get('gname')
        g_description = request.form.get('g_description')

        con = sqlite3.connect(app.config['DATABASE'])
        cursor = con.cursor()
        cursor.execute('UPDATE Genre SET name=?, description=? WHERE id=?',
                       (gname, g_description, g_id))
        con.commit()
        con.close()
        message3 = 'Genre updated successfully!'

    return render_template('change_db.html',
                           message1=message1,
                           message2=message2,
                           message3=message3)


# Run the application if this script is executed directly
if __name__ == "__main__":
    app.run(debug=True)
