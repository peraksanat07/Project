from flask import Flask, render_template, request
from config import Config
import sqlite3

app = Flask(__name__)
app.config.from_object(Config)

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
        return "nah"  # Placeholder for handling GET requests


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
    # Retrieve books associated with the author
    cur.execute("SELECT id, name FROM Books WHERE id IN (SELECT book FROM book_author WHERE author=?);", (id,))
    books = cur.fetchall()
    con.close()
    return render_template("a_details.html", author=author, books=books)


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
    # Retrieve genres associated with the book
    cur.execute("SELECT id, name FROM Genre WHERE id IN (SELECT genre FROM book_genre WHERE book=?);", (id,))
    genre = cur.fetchall()
    # Retrieve authors associated with the book
    cur.execute("SELECT id, name FROM Author WHERE id IN (SELECT author FROM book_author WHERE book=?);", (id,))
    authors = cur.fetchall()
    con.close()
    return render_template("b_details.html", book=book, genre=genre, authors=authors)


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
    return render_template("g_details.html", genre=genre)


# Login page route
@app.route('/log-in')
def log_in():
    return render_template("login.html")


# Register page route
@app.route('/register')
def register():
    return render_template("register.html")


# Welcome page route
@app.route('/welcome')
def welcome():
    return render_template("welcome.html")


if __name__ == "__main__":
    app.run(debug=True)