from flask import Flask, render_template
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
    con.close()
    return render_template("a_details.html", author=author)


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
    con.close()
    return render_template("b_details.html", book=book)


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