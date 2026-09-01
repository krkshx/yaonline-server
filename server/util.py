from xml.sax.saxutils import escape

#утилиты
def bare(j):
    return j.split('/')[0].lower() if j else ""

def q(t):
    return escape(t) if t else ""

def send(w,s):
    #отправка
    try:
        w.write(s.encode())
    except:
        pass

def feat(w, auth=False):
    #фичи
    if not auth:
        send(w, "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms><auth xmlns='http://jabber.org/features/iq-auth'/><register xmlns='http://jabber.org/features/iq-register'/></stream:features>")
    else:
        send(w, "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></stream:features>")

def roster_get(owner):
    #ростер
    from store.db import db
    cur=db.execute("select jid,name,sub from roster where owner=?", (owner,))
    out=""
    for jid,name,sub in cur.fetchall():
        out+=f"<item jid='{q(jid)}' name='{q(name)}' subscription='{sub or 'both'}'/>"
    return out
