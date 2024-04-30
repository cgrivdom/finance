import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    shares = db.execute("SELECT * FROM shares;")
    grand_total = db.execute("SELECT SUM(total_value) FROM shares;")
    balance = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])
    balance = balance[0]["cash"]

    if grand_total[0]["SUM(total_value)"] is None:
        grand_total[0]["SUM(total_value)"] = 0

    grand_total = float(grand_total[0]["SUM(total_value)"]) + float(balance)

    return render_template(
        "index.html", shares=shares, grand_total=usd(grand_total), balance=usd(balance)
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide symbol", 400)

        symbol = lookup(symbol)

        if symbol == None:
            return apology("symbol not found", 400)

        if not shares:
            return apology("must provide shares to buy", 400)

        try:
            shares = int(shares)

        except ValueError:
            return apology("shares must be a number", 400)

        if shares < 1:
            return apology("must provide a positive number of shares", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])

        if cash[0]["cash"] < symbol["price"]:
            return apology("can't afford stock", 400)

        price = symbol["price"] * shares
        cash = cash[0]["cash"] - price

        if (
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?;", cash, session["user_id"]
            )
            < 1
        ):
            return apology("purchase failed", 400)

        rows = db.execute(
            "SELECT user_id, symbol FROM shares WHERE user_id = ? AND symbol = ?;",
            session["user_id"],
            symbol["symbol"],
        )

        if len(rows) > 0:
            current_shares = db.execute(
                "SELECT shares FROM shares WHERE user_id = ? AND symbol = ?",
                session["user_id"],
                symbol["symbol"],
            )

            if len(current_shares) == 0:
                total_shares = shares
            else:
                total_shares = current_shares[0]["shares"] + shares

            total_value = float(total_shares) * float(symbol["price"])

            if (
                db.execute(
                    "UPDATE shares SET shares = ?, total_value = ? WHERE user_id = ? AND symbol = ?;",
                    total_shares,
                    usd(total_value),
                    session["user_id"],
                    symbol["symbol"],
                )
                == None
            ):
                return apology("purchase failed", 400)

            if (
                db.execute(
                    "INSERT INTO history (user_id, symbol, shares, price, date, transaction_type) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 'buy');",
                    session["user_id"],
                    symbol["symbol"],
                    shares,
                    usd(symbol["price"]),
                )
                < 1
            ):
                return apology("purchase failed", 400)

        else:
            total_value = float(shares) * float(symbol["price"])

            if (
                db.execute(
                    "INSERT INTO shares (user_id, symbol, shares, price, total_value) VALUES (?, ?, ?, ?, ?);",
                    session["user_id"],
                    symbol["symbol"],
                    shares,
                    usd(symbol["price"]),
                    usd(total_value),
                )
                < 1
            ):
                return apology("purchase failed", 400)

            if (
                db.execute(
                    "INSERT INTO history (user_id, symbol, shares, price, date, transaction_type) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 'buy');",
                    session["user_id"],
                    symbol["symbol"],
                    shares,
                    usd(symbol["price"]),
                )
                < 1
            ):
                return apology("purchase failed", 400)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    history = db.execute("SELECT * FROM history;")

    return render_template("history.html", history=history)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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

    if request.method == "POST":
        symbol = request.form.get("symbol")
        symbol = lookup(symbol)

        if symbol == None:
            return apology("symbol not found", 400)
        else:
            price = usd(symbol["price"])
            return render_template("quoted.html", symbol=symbol, price=price)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 400)

        elif not password:
            return apology("must provide password", 400)

        elif len(password) < 8:
            return apology("password must be at least 8 characters long", 400)

        elif not confirmation:
            return apology("must confirm password", 400)

        elif password != confirmation:
            return apology("passwords must match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) > 0:
            return apology("username already exists", 400)

        hash = generate_password_hash(password)

        if (
            db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?);", username, hash
            )
            == None
        ):
            return apology("registration failed", 400)

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide symbol", 400)

        check_symbol = db.execute("SELECT symbol FROM shares WHERE symbol = ?", symbol)

        if not check_symbol:
            return apology("symbol not owned", 400)

        if not shares:
            return apology("must provide shares to sell", 400)

        try:
            shares = int(shares)

        except ValueError:
            return apology("shares must be a number", 400)

        if shares < 1:
            return apology("must provide a positive number of shares", 400)

        check_shares = db.execute(
            "SELECT shares FROM shares WHERE symbol = ? AND user_id = ?",
            symbol,
            session["user_id"],
        )

        if check_shares[0]["shares"] < shares:
            return apology("shares not owned", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?;", session["user_id"])

        stock_price = lookup(symbol)
        price = stock_price["price"] * shares
        cash = cash[0]["cash"] + price

        if (
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?;", cash, session["user_id"]
            )
            < 1
        ):
            return apology("sell failed", 400)

        current_shares = db.execute(
            "SELECT shares FROM shares WHERE user_id = ? AND symbol = ?",
            session["user_id"],
            symbol,
        )
        total_shares = current_shares[0]["shares"] - shares

        stock_price = lookup(symbol)
        total_value = float(shares) * float(stock_price["price"])

        if (
            db.execute(
                "UPDATE shares SET shares = ?, total_value = ? WHERE user_id = ? AND symbol = ?;",
                total_shares,
                usd(total_value),
                session["user_id"],
                symbol,
            )
            != 1
        ):
            return apology("sell failed", 400)

        if (
            db.execute(
                "INSERT INTO history (user_id, symbol, shares, price, date, transaction_type) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 'sell');",
                session["user_id"],
                symbol,
                shares,
                usd(stock_price["price"]),
            )
            == None
        ):
            return apology("sell failed", 400)

        return redirect("/")

    else:
        symbol = db.execute("SELECT * FROM shares;")

        return render_template("sell.html", symbol=symbol)
