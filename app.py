import os
from flask import Flask, render_template, request, g, redirect, url_for
import sqlite3

app = Flask(__name__)
DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Ensure the database is only initialized once
if not os.path.exists(DATABASE):
    init_db()

@app.route("/")
def index():
    db = get_db()
    
    # Fetch the latest post (or None if no posts are in the database)
    post = db.execute('SELECT * FROM posts ORDER BY created_at DESC LIMIT 1').fetchone()
    
    # If no post is found, set comments to an empty list
    comments = []
    if post:
        # Fetch comments for the latest post if it exists
        comments = db.execute('SELECT comment, created_at FROM comments WHERE post_id = ?', (post['id'],)).fetchall()

    # Render the index template, passing post and comments (empty list if no post exists)
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
        db = get_db()
        db.execute('INSERT INTO messages (navn, epost, melding) VALUES (?, ?, ?)', (navn, epost, melding))
        db.commit()
        return "Takk for meldingen din!"
    else:
        return render_template('kontakt.html')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')





