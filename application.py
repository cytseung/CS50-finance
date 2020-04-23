import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

import logging
# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template('buy.html')
    else: # method is POST
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        sym_obj = lookup(symbol)
        if not sym_obj: # failed lookup
            return apology("Stock not found")
        else: # lookup success
            cash = db.execute('SELECT cash FROM users where id = :userid', userid = session["user_id"])[0]["cash"]
            total_price = sym_obj["price"] * shares
            if cash < total_price:
                apology("can't afford")
            cash -= total_price
            # app.logger.info(session["user_id"])
            db.execute('UPDATE users SET cash = :cash WHERE id=:userid', cash=cash, userid=session["user_id"])
            db.execute("INSERT INTO transactions (price, shares, datetime, symbol, user_id) VALUES (:price, :shares, DateTime('now'), :symbol, :user_id)",price=sym_obj["price"], shares=shares, user_id=session["user_id"], symbol=symbol)
            # app.logger.info(type(db.execute("SELECT EXISTS(SELECT 1 FROM symbols WHERE symbol=:symbol)", symbol=symbol)))
            result = db.execute("SELECT EXISTS(SELECT 1 FROM symbols WHERE symbol=:symbol)", symbol=symbol)
            string = "EXISTS(SELECT 1 FROM symbols WHERE symbol=" + "'" + symbol + "')"
            if not (result[0][string]):
                db.execute("INSERT INTO symbols (symbol, name) VALUES(:symbol, :name)", symbol=symbol, name=sym_obj["name"])
            return redirect("/")





@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")
        symbol_obj = lookup(symbol)
        name = symbol_obj["name"]
        price = symbol_obj["price"]
        symbol_got = symbol_obj["symbol"]
        return render_template("quoted.html", symbol=symbol_got, name=name, price=price)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    
    else:
        username = request.form.get("username")
        db.execute("SELECT username FROM users WHERE username = :username",username=username)
        password = request.form.get("password")
        pass_hash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",username=username, hash=pass_hash)
        return redirect("/")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
