from flask import Flask, render_template, request, session, redirect, url_for
from config import Config
import sqlite3
import re

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = "testing secret thing"


# Context processor to provide global context variables to templates
@app.context_processor
def context_processor():
    return dict(title=app.config['TITLE'])


# Homepage route
@app.route('/')
def homepage():
    return render_template("home.html")


# Search route to handle both GET and POST requests
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        # Get search term from form submission
        search = request.form.get('searchterm')       
        # Connect to the database
        con = sqlite3.connect(app.config['DATABASE'])
        cur = con.cursor()       
        # Define search queries for Books, Genre, and Author
        search_queries = [
            ("SELECT name, blurb FROM Books WHERE name LIKE ?", search),
            ("SELECT name, description FROM Genre WHERE name LIKE ?", search),
            ("SELECT name, description FROM Author WHERE name LIKE ?", search)
        ]       
        results = []       
        # Execute each query with the search term parameter
        for query, param in search_queries:
            cur.execute(query, ('%' + param + '%',))
            results.append(cur.fetchall())        
        con.close()        
        # Render search results template with retrieved data
        return render_template('search.html', search_term=search, books=results[0], genres=results[1], authors=results[2])   
    else:
        return render_template('error.html'), 404


# About page route
@app.route('/about')
def about():
    return render_template("layout.html")


# Author list route
@app.route('/author')
def author():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT id,name,image FROM Author ORDER BY id;")
    authors = cur.fetchall()
    con.close()
    return render_template("author.html", authors=authors)


# Author details route with specific author ID
@app.route('/author/<int:id>')
def author_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()
    # Retrieve author details by ID
    cur.execute("SELECT * FROM Author WHERE id=?;", (id,))
    author = cur.fetchone()
    if author:
        # Retrieve books associated with the author
        cur.execute("SELECT id, name FROM Books WHERE id IN (SELECT book FROM book_author WHERE author=?);", (id,))
        books = cur.fetchall()
        con.close()
        return render_template("a_details.html", author=author, books=books)
    else:
        return render_template("error.html"), 404


# Books list route
@app.route('/books')
def books():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT id,name,image FROM Books ORDER BY id;")
    books = cur.fetchall()
    con.close()
    return render_template("book.html", books=books)


# Book details route with specific book ID
@app.route('/books/<int:id>')
def book_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()    
    # Retrieve book details by ID
    cur.execute("SELECT * FROM Books WHERE id=?;", (id,))
    book = cur.fetchone()
    if book:
         # Retrieve genres associated with the book
        cur.execute("SELECT id, name FROM Genre WHERE id IN (SELECT genre FROM book_genre WHERE book=?);", (id,))
        genre = cur.fetchall()
        # Retrieve authors associated with the book
        cur.execute("SELECT id, name FROM Author WHERE id IN (SELECT author FROM book_author WHERE book=?);", (id,))
        authors = cur.fetchall()
        con.close()
        return render_template("b_details.html", book=book, genre=genre, authors=authors)
    else:
        return render_template("error.html"), 404

# Contact Us page route with form submission handling
@app.route('/contact_us', methods=['GET', 'POST'])
def contact_us():
    if request.method == 'POST':
        # Connect to the database and insert form data into Responses table
        with sqlite3.connect(app.config['DATABASE']) as con:
            cur = con.cursor()
            cur.execute("INSERT INTO Responses (f_name, l_name, subject) VALUES(?,?,?)", 
                        (request.form.get('firstname'), request.form.get('lastname'), request.form.get('subject')))
            con.commit()  
    return render_template("contact_us.html")


# Edit profile route
@app.route('/edit')
def edit():
    return render_template("edit.html")


# Genre list route
@app.route('/genre')
def genre():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT id,name FROM Genre ORDER BY id;")
    genres = cur.fetchall()
    con.close()
    return render_template("genre.html", genres=genres)


# Genre details route with specific genre ID
@app.route('/genre/<int:id>')
def genre_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor() 
    # Retrieve genre details by ID
    cur.execute("SELECT * FROM Genre WHERE id=?;", (id,))
    genre = cur.fetchone()
    con.close()
    if genre:
        return render_template("g_details.html", genre=genre)
    else:
        return render_template("error.html"), 404


# login
@app.route('/log-in', methods=['GET', 'POST'])
def log_in():
    message = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        con = sqlite3.connect('project.db')
        cur = con.cursor()
        cur.execute('SELECT * FROM users WHERE Username = ? AND Password = ?', (username, password))
        user = cur.fetchone()
        con.close()
        if user:
            session['loggedin'] = True
            session['userid'] = user[0]
            session['name'] = user[1]
            session['username'] = user[1]
            message = 'Logged in successfully!'
            return render_template('admin.html', message=message)
        else:
            message = 'Please enter correct email/password!'
    return render_template('login.html', message=message)


# Make function for logout session
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    return redirect(url_for('log_in'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html'), 404


# Register page route
@app.route('/register')
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form and 'age' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        age = request.form['age']
        try:
            age = int(age)
        except ValueError:
            message = 'Age must be a number!'
            return render_template('register.html', message=message)
        con = sqlite3.connect('project.db')
        cursor = con.cursor()
        cursor.execute('SELECT * FROM users WHERE Email = ?', (email,))
        account = cursor.fetchone()
        if account:
            message = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            message = 'Invalid email address!'
        elif age < 16:
            message = 'You are not old enough to register'
        elif not username or not password or not email or not age:
            message = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO users(Username, Email, Password, Age) VALUES(?, ?, ?, ?)', (username, email, password, age,))
            con.commit()
            message = 'You have successfully registered!'
            return render_template('register.html', message=message)
        con.close()
    elif request.method == 'POST':
        message = 'Please fill out the form!'
    return render_template('register.html', message=message)


# Welcome page route
@app.route('/welcome')
def welcome():
    return render_template("welcome.html")


if __name__ == "__main__":
    app.run(debug=True)