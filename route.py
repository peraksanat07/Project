# Import necessary modules and classes from Flask and other libraries
from flask import Flask, render_template, request, session, redirect, url_for
from config import Config
import sqlite3
import re

# Create an instance of the Flask class
app = Flask(__name__)
# Load configuration settings from Config object
app.config.from_object(Config)
# Set a secret key for session management
app.secret_key = "testing secret thing"

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

# Context processor to provide global context variables to templates
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
            return render_template('search.html', search_term='', books=[], genres=[], authors=[])
        print(f"Search term: {search_term}")
        # Define SQL queries for searching Books, Genre, and Author tables
        search_queries = [
            ("SELECT name, blurb FROM Books WHERE name LIKE ?", '%' + search_term + '%'),
            ("SELECT name, description FROM Genre WHERE name LIKE ?", '%' + search_term + '%'),
            ("SELECT name, description FROM Author WHERE name LIKE ?", '%' + search_term + '%')
        ]
        # Execute each query and store the results
        results = [query_db(query, (param,)) for query, param in search_queries]
        # Render the 'search.html' template with search results
        return render_template('search.html', search_term=search_term, books=results[0], genres=results[1], authors=results[2])    

# Route for the About page
@app.route('/about')
def about():
    # Render the 'layout.html' template
    return render_template("layout.html")

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
    # Query the database for the author with the specified ID
    author = query_db("SELECT * FROM Author WHERE id=?", (id,), one=True)
    if author:
        # Query the database for books associated with the author
        books = query_db("SELECT id, name FROM Books WHERE id IN (SELECT book FROM book_author WHERE author=?)", (id,))
        # Render the 'a_details.html' template with author and book details
        return render_template("a_details.html", author=author, books=books)
    # Render 'error.html' if author is not found
    return render_template("error.html"), 404

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
    # Query the database for the book with the specified ID
    book = query_db("SELECT * FROM Books WHERE id=?", (id,), one=True)
    if book:
        # Query the database for genres associated with the book
        genre = query_db("SELECT id, name FROM Genre WHERE id IN (SELECT genre FROM book_genre WHERE book=?)", (id,))
        # Query the database for authors associated with the book
        authors = query_db("SELECT id, name FROM Author WHERE id IN (SELECT author FROM book_author WHERE book=?)", (id,))
        # Render the 'b_details.html' template with book, genre, and author details
        return render_template("b_details.html", book=book, genre=genre, authors=authors)
    # Render 'error.html' if book is not found
    return render_template("error.html"), 404

# Route for the Contact Us page with form submission handling
@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    message = ''
    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        subject = request.form.get('subject')
        email = request.form.get('email')

        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Please enter valid email'
        else:
            # Connect to the database and insert form data into Responses table
            con = sqlite3.connect(app.config['DATABASE'])
            cur = con.cursor()
            cur.execute("INSERT INTO Responses (f_name, l_name, subject, email) VALUES (?, ?, ?, ?)", 
                        (firstname, lastname, subject, email))
            con.commit()
            message = 'Form Submitted!'
            
    return render_template("contact_us.html", message=message)


# Route for the Edit Profile page
@app.route('/edit')
def edit():

    # Render the 'edit.html' template
    return render_template("edit.html")

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
    # Query the database for the genre with the specified ID
    genre = query_db("SELECT * FROM Genre WHERE id=?", (id,), one=True)
    if genre:
        # Render the 'g_details.html' template with genre details
        return render_template("g_details.html", genre=genre)
    # Render 'error.html' if genre is not found
    return render_template("error.html"), 404

# Route for the Login page
@app.route('/log-in', methods=['GET', 'POST'])
def log_in():
    message = ''
    if request.method == 'POST' and all(k in request.form for k in ('username', 'password')):
        # Retrieve username and password from the form
        username, password = request.form['username'], request.form['password']
        # Query the database for the user with the provided username and password
        user = query_db('SELECT * FROM users WHERE Username = ? AND Password = ?', (username, password), one=True)
        if user:
            # Set session variables for the logged-in user
            session.update({'loggedin': True, 'userid': user[0], 'name': user[1], 'username': user[1]})
            message = 'Logged in successfully!'
            # Render the 'admin.html' template for the admin dashboard
            return render_template('admin.html', message=message)
        message = 'Please enter correct email/password!'
    # Render the 'login.html' template with a message
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

# Route for the Register page (CHECK THIS OUT)
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'age' in request.form:
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
            return render_template('register.html', message=message)
        con = sqlite3.connect('project.db')
        cursor = con.cursor()
        # Check if an account with the provided email already exists
        account = query_db('SELECT * FROM users WHERE Email = ?', (email,), one=True)
        if account:
            message = 'Account already exists!'
        elif username:
            message = 'Username already exists! Please choose another username'
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
            cursor.execute('INSERT INTO users(Username, Email, Password, Age) VALUES(?, ?, ?, ?)', (username, email, password, age,))
            con.commit()
            message = 'You have successfully registered!'
            return render_template('register.html', message=message)
        con.close()
    elif request.method == 'POST':
        message = 'Please fill out the form!'
    # Render the 'register.html' template with a message
    return render_template('register.html', message=message)


@app.route('/password',  methods=['GET', 'POST'])
def password():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmpassword']

        if not email or not password or not confirm_password:
            message = 'Please fill out the form!'
            return render_template("password.html", message=message)

        if password != confirm_password:
            message = 'Passwords do not match!'
            return render_template("password.html", message=message)

        user = users.query.filter_by(email=email).first()
        if user:
            # Update the user's password
            user.set_password(password)
            session.commit()  # Save changes to the database
            message = 'Password updated successfully'
        else:
            message = 'User not found'

    return render_template("password.html", message=message)

# Route for the Welcome page (admin dashboard)
@app.route('/admin')
def admin():

    # Render the 'admin.html' template
    return render_template("admin.html")

# Run the application if this script is executed directly
if __name__ == "__main__":
    app.run(debug=True)