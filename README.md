# Finance

## Description:
**Finance** is a Flask based web application that allows users to buy an sell stocks.

## Usage:

With `Flask` running on a local machine, the user should enter the command `flask run` on a terminal window to run the web application, making sure to enter the command after moving into the program directory via `cd finance`

## Contents of the project:

**Finance** is comprised of seven different files and directories:

`static` -> This is a directory that contains our CSS file and our app icon.

`templates` -> This is a directory that contains our HTML templates

`app.py` -> The purpose of this file is to provide the necessary backend logic such as register and log in, with its corresponding actions on the database as well as querying the API to search and buy/sell stocks

`finance.db` -> The purpose of this file is to provide the proper SQLite3 database for the app

`helpers.py` -> The purpose of this file is to provide the necessary functions for `app.py` such as handling required log in and querying stocks

`README.md` -> Provides an overview of the project.