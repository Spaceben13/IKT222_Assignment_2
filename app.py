import os
import re
from flask import Flask, render_template, request, g, redirect, url_for
import sqlite3

app = Flask(__name__)
DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Initialize the database if needed
def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            comment TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts(id)
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            navn TEXT NOT NULL,
            epost TEXT NOT NULL,
            melding TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        db.commit()

# Ensure the database is only initialized once
if not os.path.exists(DATABASE):
    init_db()

@app.route("/")
def index():
    db = get_db()
    post = db.execute('SELECT * FROM posts ORDER BY created_at DESC LIMIT 1').fetchone()
    
    
    comments = []
    if post:
        comments = db.execute('SELECT comment, created_at FROM comments WHERE post_id = ?', (post['id'],)).fetchall()

    return render_template('index.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    comment = request.form['comment']
    db = get_db()
    db.execute('INSERT INTO comments (post_id, comment) VALUES (?, ?)', (post_id, comment))
    db.commit()
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/post/<int:post_id>')
def view_post(post_id):
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    comments = db.execute('SELECT comment, created_at FROM comments WHERE post_id = ?', (post_id,)).fetchall()

    return render_template('index.html', post=post, comments=comments)

@app.route("/om_meg")
def om_meg():
    return render_template("om_meg.html")

@app.route('/kontakt', methods=['GET', 'POST'])
def kontakt():
    if request.method == 'POST':  
        navn = request.form['navn']
        epost = request.form['epost']
        melding = request.form['melding']
        
        if navn and re.match(r'[^@]+@[^@]+\.[^@]+', epost) and melding:
            db = get_db()
            db.execute('INSERT INTO messages (navn, epost, melding) VALUES (?, ?, ?)', (navn, epost, melding))
            db.commit()
            return "Takk for meldingen din!"
        else:
            return "Ugyldig e-postadresse eller tomme felter. Vennligst prøv igjen."
    else:
        return render_template('kontakt.html')

@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # Insert the new post into the posts table
        db = get_db()
        db.execute('INSERT INTO posts (title, content) VALUES (?, ?)', (title, content))
        db.commit()
        
        return redirect(url_for('index'))
    else:
        return render_template('create_post.html')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')






