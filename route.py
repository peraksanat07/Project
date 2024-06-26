from flask import Flask, render_template, request
from config import Config
import sqlite3
# import random

app = Flask(__name__)
app.config.from_object(Config)


@app.context_processor
def context_processor():
  return dict(title=app.config['TITLE'])


@app.route('/')
def homepage():
    return render_template("home.html")


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        # in other words, someone clicked submit, 'POSTing' info
        # back to the server
        search = request.form.get('searchterm')
        con = sqlite3.connect(app.config['DATABASE'])
        cur = con.cursor()
        cur.execute("SELECT name, blurb FROM Books WHERE name LIKE ?", ('%' + search + '%',))
        search1 = cur.fetchall()
        cur = con.cursor()        
        cur.execute("SELECT name, description FROM Genre WHERE name LIKE ?", ('%' + search + '%',))
        search2 = cur.fetchall()
        cur = con.cursor()        
        cur.execute("SELECT name, description FROM Author WHERE name LIKE ?", ('%' + search + '%',))   
        search3 = cur.fetchall()     
        con.close()
        # here is where you would do a query on your table for the search term

        return render_template('search.html', search_term=search, books=search1, genres=search2, authors=search3)
        # return f'You asked to search for \"{search, search1, search2, search3}\"'
    else: 
        return "nah"
        


@app.route('/about')
def about():
    return render_template("layout.html")


@app.route('/contact_us')
def contact_us():

    return render_template("contact_us.html")


@app.route('/log-in')
def log_in():
    return render_template("login.html")

@app.route('/author')
def author():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT id,name FROM Author ORDER BY id;")
    authors = cur.fetchall()
    con.close()
    return render_template("author.html", authors=authors)


@app.route('/author/<int:id>')
def author_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM Author WHERE id=?;",(id,))
    author = cur.fetchone()
    cur = con.cursor()
    # cur.execute("SELECT book FROM book_author WHERE author=?;",(author,))
    # book_id = cur.fetchall()
    cur.execute("SELECT id, name FROM Books WHERE id IN (SELECT book FROM book_author WHERE author=?)",(id,))
    books = cur.fetchall()
    con.close()
    return render_template("a_details.html", author=author, books=books)


@app.route('/books')
def books():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT id,name FROM Books ORDER BY id;")
    books = cur.fetchall()
    con.close()
    return render_template("book.html", books=books)


@app.route('/books/<int:id>')
def book_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM Books WHERE id=?;",(id,))
    book = cur.fetchone()
    cur.execute("SELECT id, name FROM Genre WHERE id IN (SELECT genre FROM book_genre WHERE book=?)",(id,))
    genre = cur.fetchall()
    cur = con.cursor()
    cur.execute("SELECT id, name FROM Author WHERE id IN (SELECT author FROM book_author WHERE book=?)",(id,))
    authors = cur.fetchall()
    con.close()
    return render_template("b_details.html", book=book, genre=genre, authors=authors)


@app.route('/genre')
def genre():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT id,name FROM Genre ORDER BY id;")
    genres = cur.fetchall()
    con.close()
    return render_template("genre.html", genres=genres)


@app.route('/genre/<int:id>')
def genre_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM Genre WHERE id=?;",(id,))
    genre = cur.fetchone()
    con.close()
    return render_template("g_details.html", genre=genre)


if __name__ == "__main__":
    app.run(debug=True)