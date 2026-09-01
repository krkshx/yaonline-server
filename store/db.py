import sqlite3
from server.cfg import D

#база
db = sqlite3.connect("ya.db", check_same_thread=False)
db.execute("create table if not exists u (jid text primary key, user text, domain text, pass text)")
db.execute("create table if not exists roster (owner text, jid text, name text, sub text, primary key(owner,jid))")
db.execute("create table if not exists msg (id integer primary key autoincrement, frm text, tob text, body text, ts int, done int default 0)")
db.commit()

#пресеты
for u,p in [("babaev","admin"),("krksh","admin")]:
    bj=f"{u}@{D}".lower()
    if not db.execute("select 1 from u where jid=?", (bj,)).fetchone():
        db.execute("insert into u (jid,user,domain,pass) values (?,?,?,?)", (bj,u,D,p))
db.commit()

#друзья
for a,b in [("babaev@ya.ru","krksh@ya.ru"),("krksh@ya.ru","babaev@ya.ru")]:
    if not db.execute("select 1 from roster where owner=? and jid=?", (a,b)).fetchone():
        db.execute("insert into roster (owner,jid,name,sub) values (?,?,?,?)", (a,b,b.split("@")[0],"both"))
db.commit()
