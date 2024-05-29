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


@app.route('/author')
def author():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT name FROM Author ORDER BY id;")
    author = cur.fetchall()
    con.close()
    return render_template("author.html", author=author)


@app.route('/author/<int:id>')
def author_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM Author WHERE id=?;",(id,))
    authors = cur.fetchone()
    con.close()
    return render_template("a_details.html", authors=authors)


@app.route('/books')
def books():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT name FROM Books ORDER BY id;")
    book = cur.fetchall()
    con.close()
    return render_template("book.html", book=book)


@app.route('/books/<int:id>')
def book_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM Books WHERE id=?;",(id,))
    books = cur.fetchone()
    con.close()
    return render_template("b_details.html", books=books)


@app.route('/genre')
def genre():
    con = sqlite3.connect(app.config['DATABASE'])
    cur = con.cursor()
    cur.execute("SELECT name FROM Genre ORDER BY id;")
    genre = cur.fetchall()
    con.close()
    return render_template("genre.html", genre=genre)


@app.route('/genre/<int:id>')
def genre_details(id):
    con = sqlite3.connect('project.db')
    cur = con.cursor()
    cur.execute("SELECT * FROM Genre WHERE id=?;",(id,))
    genres = cur.fetchone()
    con.close()
    return render_template("g_details.html", genres=genres)


if __name__ == "__main__":
    app.run(debug=True)