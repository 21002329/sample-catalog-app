# Sample Item Catalog Web App
A simple item catalog web application that the users can see the available under specific categories. Users also can sign in with their Google account to add, update, delete items under available item categories.

## Getting Started
### Prerequisites
The program is written in Python 3. You can download it from https://www.python.org/downloads/.

Flask framework is used for web functionalities. You can download it from https://pypi.python.org/pypi/Flask/.

SQLAlchemy is used as the ORM. You can download it from http://www.sqlalchemy.org/download.html.

## Setting up
Initialize the data model with:
```
python3 model.py
```

To populate the database with some predefined categories, you can use:
```
python3 categories.py
```

Start the web-server with:
```
python3 app.py
```
Default configuration listens from port 5000.

Homepage can be then accessed from http://localhost:$PORT/.

### Styling
PEP8 - Style Guide has been used for the project, please refer to https://www.python.org/dev/peps/pep-0008/.