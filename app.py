import os
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/om_meg")
def om_meg():
    return render_template("om_meg.html")

@app.route('/kontakt', methods=['GET', 'POST'])
def kontakt():
    if request.method == 'POST':
        # Her kan du legge til kode for å håndtere innsending av kontaktskjemaet.
        # For eksempel, lagre dataene i en database eller sende en e-post.
        return "Takk for meldingen din!"
    else:
        return render_template('kontakt.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')