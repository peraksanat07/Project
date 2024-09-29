# Import necessary modules and classes from Flask and other libraries
from flask import Flask, render_template, request, session, redirect, \
    url_for, g
import os
from werkzeug.utils import secure_filename
from config import Config
from flask_bcrypt import Bcrypt
import sqlite3
from itsdangerous import URLSafeTimedSerializer
import smtplib
from email.mime.text import MIMEText


# Create an instance of the Flask class
app = Flask(__name__)
bcrypt = Bcrypt(app)
# Load configuration settings from Config object
app.config.from_object(Config)
# Set a secret key for session management
app.secret_key = "testing secret thing"


@app.before_request
def make_session_permanent():
    # function is executed before each request to the application for admin.
    # It sets the session to be permanent, meaning the session will last
    # until the user explicitly logs out or the session timeout occurs.
    session.permanent = True


def generate_token(email):
    # Generate a secure token for the given email
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=os.getenv("SALT"))


def confirm_token(token, expiration=3600):
    # Confirm the token and return the email if valid
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        email = serializer.loads(
            token, salt=os.getenv("SALT"), max_age=expiration
        )
        return email
    except Exception:
        return False


def mail(email, token):
    # Send an email containing a reset password link
    try:
        receiver = email
        sender = 'projectlibrary91@gmail.com'
        # uses app password for more security
        password = 'frcpnkdvjdgebxyy'
        subject = "Reset password in the  system"
        senderName = "System"

        smtpserver = smtplib.SMTP('smtp.gmail.com', 587)
        smtpserver.starttls()
        smtpserver.login(sender, password)
        reset_link = url_for("reset_password", token=token, _external=True)
        # mail body
        mail_body = """
        Dear User,
        You can reset your password by clicking on the link below:
        {0}
        Note that this may not work due to local hosts on different laptops.
        If you did not request this, please ignore this email.
        """.format(reset_link)

        # compose email
        msg = MIMEText(mail_body)

        msg['Subject'] = subject
        msg['From'] = senderName + " <%s>" % sender
        msg['To'] = receiver
        # send email
        smtpserver.sendmail(sender, [receiver], msg.as_string())
        smtpserver.quit()
        return True
    except Exception:
        return False


def ensure_logged_in_or_error():
    # Ensure the user is logged in or return an error page
    if 'userid' not in session:
        return render_template('error.html')


def allowed_file(filename):
    # Check if the file has an allowed extension
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
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


# Helper function to get the database connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row  # Return rows as dictionaries
    return g.db


# Helper function to interact with the database
def update_db(query, args=()):
    # Connect to the database using the path specified in the config
    db = get_db()
    cur = db.execute(query, args)
    db.commit()  # Make sure to commit changes
    cur.close()


def update_last_id(query, args=()):
    # Executes the given SQL query and returns the ID of the last row inserted.
    # It connects to the database, executes the query with provided arguments,
    # commits the transaction to make the changes persistent, and retrieves
    # the ID of the last row that was inserted using `lastrowid`.
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    # Get the ID of the last inserted row
    last_id = cur.lastrowid
    cur.close()
    return last_id


def truncate_text(text, max_length=50):
    # Truncates the given text to a specified maximum length, appending '...'
    # if the text exceeds the max length. This function ensures that long
    # text strings are shortened for display purposes.
    if len(text) > max_length:
        # Return truncated text with ellipsis
        return text[:max_length] + '...'
    # Return text as is if within the max length
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
                                       max_length=50)
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
                            (SELECT book FROM book_author WHERE author=?)",
                             (id,))
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
            pw_hash = bcrypt.generate_password_hash(password, 10)
            user = bcrypt.check_password_hash(pw_hash, password)

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
        # age range check
        if int(age) > 100 or int(age) < 16:
            message = 'age must be between 16 and 100'
            return render_template('register.html', message=message,
                                   username=username, email=email, age=age)
        con = sqlite3.connect('project.db')
        cursor = con.cursor()
        # Check if an account with the provided email already exists
        account = query_db('SELECT * FROM users WHERE Email = ?', (email,),
                           one=True)
        if account:
            message = 'Account already exists!'
        elif password != confirmpassword:
            message = 'Passwords do not match!'
        else:
            # Insert new user into the database
            enc_password = bcrypt.generate_password_hash(password, 10)

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


# Route for the Welcome page (admin dashboard)
@app.route('/admin')
def admin():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    # Check if 'name', 'email', and 'age' exist in the session
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
        # Execute each query in the list and store results
        results = [query_db(query, param) for query, param in search_queries]

        return render_template('admin.html', name=name, email=email, age=age,
                               books=results[0], genres=results[1],
                               authors=results[2])


@app.route('/edit', methods=['GET', 'POST'])
def edit():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    message = ''
    # Get the username from the session
    name = session.get("name")
    if request.method == 'POST':
        # Get form data submitted by the user
        email = request.form['email']
        age = request.form['age']
        password = request.form['password']
        confirm_password = request.form['confirmpassword']
        # Check if the age is within the allowed range
        if int(age) > 100 or int(age) < 16:
            message = 'You are out of age range to register'
            return render_template('edit.html', name=name, age=age,
                                   email=email, message=message)
        # Validate form data (e.g., check if passwords match)
        if password != confirm_password:
            message = 'Passwords do not match!'
            return render_template('edit.html', name=name, message=message)
        # Get the user ID from the session
        user_id = session.get('userid')

        if user_id:
            # Check if the new username or email is already taken
            existing_user = query_db('SELECT * FROM users WHERE Username = ?',
                                     (name,),
                                     one=True)
            if existing_user:
                # Hash the new password using bcrypt
                hashed_password = bcrypt.generate_password_hash(password, 10)
                # Update the user's information
                update_db("UPDATE users SET Email = ?, Age = ?, Password = ? \
                          WHERE id = ?",
                          (email, int(age), hashed_password, user_id))
                message = 'Profile updated successfully!'
                # Success message
            else:
                # If user does not exist, show error
                message = 'User not valid.'

    return render_template('edit.html', name=name, message=message)


@app.route('/password', methods=['GET', 'POST'])
def password():
    # Handle the password reset request
    message = ''
    if request.method == 'POST':
        # Get the email address from the form.
        email = request.form.get("email")
        con = sqlite3.connect(app.config['DATABASE'])
        cursor = con.cursor()
        # Check if the email exists in the 'users' table.
        user = cursor.execute('SELECT * FROM users WHERE Email = ?',
                              (email,)).fetchone()

        if user:
            # Generate a password reset token for the user.
            token = generate_token(email)
            # Send the reset link via email.
            mailed = mail(email, token)
            # If the email is sent successfully, notify the user
            if mailed:
                # If there was an issue sending the email, show error message
                message = f"The password reset link has been sent to {email}."
            else:
                # If the email doesn't exist in the database, show error
                message = "Couldn't send the reset link. Please try again."
        else:
            message = "This email does not exist in our records."
        con.close()
    # Render the password reset page with a message (success or error)
    return render_template("password.html", message=message)


@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    # Initialize the message variable
    message = ''
    # Get the token from the URL parameters
    token = request.args.get("token")
    # If there is no token, render the error page
    if not token:
        return render_template('error.html')
    # If the request method is GET (when the user first visits the page)
    if request.method == "GET":
        # Confirm and decode the token to get the email
        email = confirm_token(token)
        # Store the email in session to use in the POST request
        session['reset_email'] = email
        # If the email is valid (token confirmation is successful)
        if email:
            return render_template("reset_password.html", email=email,
                                   token=token, message=message)
        else:
            # If the token is invalid, render the error page
            return render_template('error.html')
    # If the request method is POST (when the user submits the form)
    if request.method == "POST":
        # Get the email from the session
        email = session.get('reset_email')
        # Get the password and confirmation password from the form input
        password = request.form.get("password")
        confirm_password = request.form.get("confirmpassword")

        # Check if the passwords match
        if password != confirm_password:
            message = "Passwords do not match."
            # Re-render the reset password page with an error message
            return render_template("reset_password.html", email=email,
                                   token=token, message=message)
        # Hash the new password
        hashed_password = bcrypt.generate_password_hash(password, 10)
        # Update the user's password in the database using their email
        update_db('UPDATE users SET Password = ? WHERE Email = ?',
                  (hashed_password, email))
        # Set a success message
        message = f"Password successfully updated for {email}."
        return render_template("reset_password.html", message=message,
                               success=True)
    # If the request method is neither GET nor POST, render the error page
    return render_template("error.html")


@app.route('/delete_account', methods=['POST'])
def delete_account():
    # Check if user is logged in
    result = ensure_logged_in_or_error()
    if result:
        return result
    user_id = session.get('userid')
    if user_id:
        # Delete the user's account
        update_db("DELETE FROM users WHERE id = ?", (user_id,))
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
    # Retrieve authors and genres to display in the form
    authors = query_db("SELECT * FROM Author", (),)
    genres = query_db("SELECT * FROM Genre", (),)
    # Dictionary to hold messages for each form section (author, book, genre)
    message = {'author': '', 'book': '', 'genre': ''}
    # Handle author submission
    if 'aname' in request.form and 'a_description' in request.form:
        aname = request.form.get('aname')
        a_description = request.form.get('a_description')
        # Handle image upload
        if 'a_image' not in request.files:
            # Check if the file part exists
            message['author'] = 'No file selected for author image.'
        # Get the uploaded file
        file = request.files['a_image']
        if file.filename == '':
            # Check if a file was selected
            message['author'] += 'No selected file'
        # Check if the uploaded file is valid and save it to path
        if file and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['AUTHOR_IMAGE_FOLDER'],
                                   image_filename))
        # Check if all required fields are filled before inserting to database
        if aname and a_description and image_filename:
            update_db('INSERT INTO Author (name, description, image) \
                           VALUES (?, ?, ?)', (aname, a_description,
                                               os.path.join(app.config
                                                            ['AUTHOR_FOLDER'],
                                                            image_filename)))
            # Use relative path
            message['author'] += 'Author added successfully!'
        else:
            message['author'] += 'Author submission failed. '
    # Handle book submission
    elif 'bname' in request.form and 'blurb' in request.form:
        bname = request.form.get('bname')
        blurb = request.form.get('blurb')
        author_ids = request.form.getlist('authors')
        genre_ids = request.form.getlist('genres')
        # Handle image upload for the book
        if 'b_image' not in request.files:
            # Check if a file was selected
            message['book'] += 'No file part'
        # Get the uploaded file
        file = request.files['b_image']
        if file.filename == '':
            message['book'] += 'No selected file'
        # Check if the uploaded file is valid and save it
        if file and allowed_file(file.filename):
            # Secure the filename
            image_filename = secure_filename(file.filename)
            # save to path
            file.save(os.path.join(app.config['BOOK_IMAGE_FOLDER'],
                                   image_filename))
        # Check if all required fields are filled before inserting to database
        if bname and blurb and image_filename:
            # Get the ID of the newly inserted book
            book_id = update_last_id("INSERT INTO Books (name, blurb, image)\
                                        VALUES (?, ?, ?)",
                                     (bname, blurb,
                                      os.path.join(app.config['BOOK_FOLDER'],
                                                   image_filename)))
            # Ensure author_ids and genre_ids are integers
            author_ids = [int(a_id) for a_id in author_ids]
            genre_ids = [int(g_id) for g_id in genre_ids]
            # Insert into BookAuthor association table
            for author_id in (author_ids):
                update_db('INSERT INTO book_author (book, author) \
                          VALUES (?, ?)',
                          (book_id, author_id))

            # Insert into BookGenre association table
            for genre_id in (genre_ids):
                update_db('INSERT INTO book_genre (book, genre) VALUES (?, ?)',
                          (book_id, genre_id))
            message['book'] += ' Book added successfully!'

        # Handle genre submission
    elif 'gname' in request.form and 'g_description' in request.form:
        gname = request.form.get('gname')
        g_description = request.form.get('g_description')
        # Check if all required fields are filled before inserting to database
        if gname and g_description:
            update_db('INSERT INTO Genre (name, description) \
                           VALUES (?, ?)', (gname, g_description))
            message['genre'] += ' Genre added successfully!'
    # Render the template with messages, retrieved authors and genres
    return render_template('add_db.html',
                           message=message, authors=authors, genres=genres)


@app.route('/delete_database', methods=['GET', 'POST'])
def delete_database():
    # Check if user is logged in; if not, handle the error accordingly
    result = ensure_logged_in_or_error()
    if result:
        return result
    # Dictionary to hold messages for deletion results for author, book, genre
    messages = {'a_id': '', 'b_id': '', 'g_id': ''}
    # Handle form submission for deletion when the request method is POST
    if request.method == 'POST':
        a_id = request.form.get('a_id')
        b_id = request.form.get('b_id')
        g_id = request.form.get('g_id')
        # Author ID check
        if a_id:
            # Check if the author ID exists in the database
            if query_db('SELECT id FROM Author WHERE id=?', (a_id,), one=True):
                # Delete the author from the database if found
                update_db('DELETE FROM Author WHERE id=?', (a_id,))
                messages['a_id'] = 'Author deleted successfully!'
            else:
                messages['a_id'] = 'Author ID not found in the database!'
        # Book ID check
        if b_id:
            # Check if the book ID exists in the database
            if query_db('SELECT id FROM Books WHERE id=?', (b_id,), one=True):
                # Delete the book from the database if found
                update_db('DELETE FROM Books WHERE id=?', (b_id,))
                messages['b_id'] = 'Book deleted successfully!'
            else:
                messages['b_id'] = 'Book ID not found in the database!'
        # Genre ID check
        if g_id:
            # Check if the genre ID exists in the database
            if query_db('SELECT id FROM Genre WHERE id=?', (g_id,), one=True):
                # Delete the genre from the database if found
                update_db('DELETE FROM Genre WHERE id=?', (g_id,))
                messages['g_id'] = 'Genre deleted successfully!'
            else:
                messages['g_id'] = 'Genre ID not found in the database!'
    # Render the delete_db.html template with messages regarding deletion
    return render_template("delete_db.html", messages=messages)


# Run the application if this script is executed directly
if __name__ == "__main__":
    app.run(debug=True)
