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
    if "isBought" not in session:
        session["isBought"] = False
    if "isSold" not in session:
        session["isSold"] = False    
    isBought = session["isBought"]
    session["isBought"] = False
    isSold = session["isSold"]
    session["isSold"] = False
    symbols = []
    shares = []
    names=[]
    prices=[]
    totals=[]
    portfolio = db.execute("SELECT SUM(shares), symbol_id FROM transactions WHERE user_id = :userid GROUP BY symbol_id HAVING SUM(shares) > 0 ORDER BY symbol_id;", userid=session["user_id"])
    for dict_item in portfolio:
        symbol = db.execute("SELECT symbol FROM symbols WHERE id=:symbol_id",symbol_id = dict_item["symbol_id"])[0]["symbol"]
        symbols.append(symbol)
        shares.append(dict_item["SUM(shares)"])
    
    for symbol,share in zip(symbols,shares):
        sym_obj = lookup(symbol)
        names.append(sym_obj["name"])
        prices.append(usd(sym_obj["price"]))
        totals.append(sym_obj["price"] * share)
   

    cash = (db.execute('SELECT cash FROM users where id = :userid', userid = session["user_id"])[0]["cash"])
    total = sum(totals) + cash
    cash = usd(cash)
    total = usd(total)
    new_totals = [usd(total) for total in totals]
    iterable = (zip(symbols,names,shares,prices,new_totals))
    return render_template("index.html", symbols=symbols, shares=shares, iterable=iterable, cash=cash, total=total, isBought=isBought, isSold=isSold)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    session["isBought"] = False
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
                return apology("can't afford")
            cash -= total_price
            # check whether exists in symbol table
            result = db.execute("SELECT EXISTS(SELECT 1 FROM symbols WHERE symbol=:symbol)", symbol=symbol)
            string = "EXISTS(SELECT 1 FROM symbols WHERE symbol=" + "'" + symbol + "')"
            if not (result[0][string]):
                db.execute("INSERT INTO symbols (symbol, name) VALUES(:symbol, :name)", symbol=symbol, name=sym_obj["name"])
            symbol_id = db.execute("SELECT id FROM symbols where symbol=:symbol", symbol=symbol)[0]["id"]
            # app.logger.info(symbol_id)
            db.execute('UPDATE users SET cash = :cash WHERE id=:userid', cash=cash, userid=session["user_id"])
            db.execute("INSERT INTO transactions (price, shares, datetime, symbol_id, user_id) VALUES (:price, :shares, DateTime('now'), :symbol_id, :user_id)",price=sym_obj["price"], shares=shares, user_id=session["user_id"], symbol_id=symbol_id)
            # app.logger.info(type(db.execute("SELECT EXISTS(SELECT 1 FROM symbols WHERE symbol=:symbol)", symbol=symbol)))
            session["isBought"] = True
            return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT price,shares, datetime, symbol_id FROM transactions WHERE user_id=:userid ORDER BY datetime",userid=session["user_id"])
    #app.logger.info(history)
    symbols=[]
    shares=[]
    prices=[]
    datetime=[]
    # names = []

    for dict_item in history:
        symbol = db.execute("SELECT symbol FROM symbols WHERE id=:symbol_id",symbol_id = dict_item["symbol_id"])[0]["symbol"]
        #name = db.execute("SELECT symbol FROM symbols WHERE id=:symbol_id",symbol_id = dict_item["symbol_id"] )[0]["name"]
        shares.append(dict_item["shares"])
        prices.append(usd(dict_item["price"]))
        symbols.append(symbol)
        datetime.append(dict_item["datetime"])
        #names.append(name)
    #iterable = zip(symbols, names,shares,prices,datetime)
    iterable = zip(symbols, shares,prices,datetime)
    # cash = db.execute('SELECT cash FROM users where id = :userid', userid = session["user_id"])[0]["cash"]
    # cash = usd(cash)
    return render_template("history.html",iterable=iterable)


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
    session["isSold"] = False
    symbols = []
    shares = []
    portfolio = db.execute("SELECT SUM(shares), symbol_id FROM transactions WHERE user_id = :userid GROUP BY symbol_id HAVING SUM(shares) > 0 ORDER BY symbol_id;", userid=session["user_id"])
    for dict_item in portfolio:
        symbol = db.execute("SELECT symbol FROM symbols WHERE id=:symbol_id",symbol_id = dict_item["symbol_id"])[0]["symbol"]
        symbols.append(symbol)
        shares.append(dict_item["SUM(shares)"])
    sym_dict = dict(zip(symbols, shares))   
    if request.method == "GET":
        return render_template("sell.html", symbols=symbols, shares=shares, sym_dict=sym_dict)
    else:
        symbol = request.form.get("symbol")
        shares_to_sell = int(request.form.get("shares"))
        for k in sym_dict:
           if symbol == k:
               shares_avail = sym_dict[symbol]
               break
        if shares_to_sell > shares_avail:
            apology("too many shares")
        else:
            sym_obj = lookup(symbol)
            if not sym_obj: # failed lookup
                return apology("Stock not found")
            else:
                cash = db.execute('SELECT cash FROM users where id = :userid', userid = session["user_id"])[0]["cash"]
                total_price = sym_obj["price"] * shares_to_sell
                cash += total_price
                db.execute('UPDATE users SET cash = :cash WHERE id=:userid', cash=cash, userid=session["user_id"])
                symbol_id = db.execute("SELECT id FROM symbols where symbol=:symbol", symbol=symbol)[0]["id"]
                db.execute("INSERT INTO transactions (price, shares, datetime, symbol_id, user_id) VALUES (:price, :shares, DateTime('now'), :symbol_id, :user_id)",price=sym_obj["price"], shares=-shares_to_sell, user_id=session["user_id"], symbol_id=symbol_id)
                session["isSold"] = True
                return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
