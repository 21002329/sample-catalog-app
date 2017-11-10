from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from model import Base, Category, Item, User

engine = create_engine('sqlite:///item-catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Delete everything
session.query(Category).delete()
session.query(Item).delete()
session.query(User).delete()

session.commit()
print("Deleted everything!")

# Add some categories
category1 = Category(name="Soccer")
session.add(category1)
category2 = Category(name="Basketball")
session.add(category2)
category3 = Category(name="Baseball")
session.add(category3)
category4 = Category(name="Frisbee")
session.add(category4)
category5 = Category(name="Snowboarding")
session.add(category5)
category6 = Category(name="Rock Climbing")
session.add(category6)
category7 = Category(name="Foosball")
session.add(category7)
category8 = Category(name="Skating")
session.add(category8)
category9 = Category(name="Hockey")
session.add(category9)

session.commit()
print("Added some categories!")
