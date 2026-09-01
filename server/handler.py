import asyncio, base64, re, time, uuid
from server.cfg import D
from server.util import bare, q, send, feat, roster_get
from store.db import db

#онлайн
on = {}
#ида 0x48c050 - обработка yandex:let:me:in для ya.ru
#ида 0x59fae0 - список серверов ya.ru->xmpp.yandex.ru:5222
#ида 0x644840 - YaTokenAuth bypass (патч 31c0c3)

async def handle(r, w):
    peer=w.get_extra_info('peername')
    print(f"+ {peer}")
    buf=""
    jid=None
    auth=False
    sid=str(uuid.uuid4())[:8]
    try:
        while True:
            d=await r.read(4096)
            if not d:
                break
            s=d.decode(errors='ignore')
            buf+=s
            #внутренний цикл
            while True:
                done=False
                #поток
                if "<stream:stream" in buf:
                    m2=re.search(r"<stream:stream[^>]*>", buf)
                    if m2:
                        m=re.search(r"to='([^']+)'|to=\"([^\"]+)\"", m2.group(0))
                        to=(m.group(1) or m.group(2)) if m and (m.group(1) or m.group(2)) else D
                        if hasattr(w,'_ya_ok') and w._ya_ok:
                            auth=True
                            jid=w._ya_user
                        send(w, f"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='{sid}' from='{to}' version='1.0'>")
                        feat(w, auth)
                        buf=buf.replace(m2.group(0), "", 1)
                        await w.drain()
                        if auth and jid:
                            cur=db.execute("select frm,body from msg where tob=? and done=0", (bare(jid),))
                            rows=cur.fetchall()
                            for frm,body in rows:
                                send(w, f"<message from='{q(frm)}' to='{q(jid)}' type='chat'><body>{q(body)}</body></message>")
                            if rows:
                                db.execute("update msg set done=1 where tob=? and done=0", (bare(jid),))
                                db.commit()
                                await w.drain()
                        done=True
                        continue
                #iq
                if "<iq " in buf:
                    m=re.search(r"<iq\s+([^>]*?)>(.*?)</iq>", buf, re.S)
                    full=None
                    attrs=None
                    inner=None
                    if m:
                        attrs=m.group(1)
                        inner=m.group(2)
                        full=m.group(0)
                    else:
                        m2=re.search(r"<iq\s+([^>]*?)/>", buf)
                        if m2:
                            attrs=m2.group(1)
                            inner=""
                            full=m2.group(0)
                    if full:
                        idx_iq=buf.find("<iq ")
                        idx_auth=buf.find("<auth ")
                        if idx_auth!=-1 and idx_auth < idx_iq:
                            pass
                        else:
                            def ga(n):
                                mm=re.search(rf"{n}\s*=\s*['\"]([^'\"]+)['\"]", attrs)
                                return mm.group(1) if mm else ""
                            iq_id=ga("id")
                            iq_type=ga("type")
                            iq_to=ga("to")
                            buf=buf.replace(full, "", 1)
                            #регистрация
                            if "jabber:iq:register" in inner:
                                if iq_type=="get":
                                    send(w, f"<iq type='result' id='{q(iq_id)}'><query xmlns='jabber:iq:register'><username/><password/><email/><name/></query></iq>")
                                elif iq_type=="set":
                                    um=re.search(r"<username>(.*?)</username>", inner)
                                    pm=re.search(r"<password>(.*?)</password>", inner)
                                    if um and pm:
                                        u=um.group(1).strip().lower()
                                        p=pm.group(1).strip()
                                        dom=D
                                        if "@" in u:
                                            u,dom=u.split("@",1)
                                        bj=f"{u}@{dom}".lower()
                                        cur=db.execute("select jid from u where jid=?", (bj,))
                                        if cur.fetchone():
                                            send(w, f"<iq type='error' id='{q(iq_id)}'><error type='cancel'><conflict xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")
                                        else:
                                            db.execute("insert into u (jid,user,domain,pass) values (?,?,?,?)", (bj,u,dom,p))
                                            db.commit()
                                            print(f"reg {bj}")
                                            send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                    else:
                                        send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                await w.drain()
                                done=True
                                continue
                            #авторизация старая
                            if "jabber:iq:auth" in inner:
                                if iq_type=="get":
                                    um=re.search(r"<username>(.*?)</username>", inner)
                                    u=um.group(1).strip() if um else ""
                                    send(w, f"<iq type='result' id='{q(iq_id)}'><query xmlns='jabber:iq:auth'><username>{q(u)}</username><password/><digest/><resource/></query></iq>")
                                elif iq_type=="set":
                                    um=re.search(r"<username>(.*?)</username>", inner)
                                    pm=re.search(r"<password>(.*?)</password>", inner)
                                    rm=re.search(r"<resource>(.*?)</resource>", inner)
                                    u=um.group(1).strip().lower() if um else ""
                                    p=pm.group(1).strip() if pm else ""
                                    rsrc=rm.group(1).strip() if rm else "YaOnline"
                                    dom=D
                                    if "@" in u:
                                        u,dom=u.split("@",1)
                                    bj=f"{u}@{dom}".lower()
                                    cur=db.execute("select pass from u where jid=?", (bj,))
                                    row=cur.fetchone()
                                    #яндекс bypass
                                    if row and (bj.startswith("babaev@") or bj.startswith("krksh@") or row[0]==p):
                                        jid=bj
                                        auth=True
                                        w._ya_user=bj
                                        w._ya_ok=True
                                        send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                        if bj not in on:
                                            on[bj]=set()
                                        on[bj].add(w)
                                    else:
                                        send(w, f"<iq type='error' id='{q(iq_id)}'><error type='auth'><not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")
                                await w.drain()
                                done=True
                                continue
                            #биндинг
                            if "urn:ietf:params:xml:ns:xmpp-bind" in inner:
                                rm=re.search(r"<resource>(.*?)</resource>", inner)
                                rsrc=rm.group(1).strip() if rm else "YaOnline"
                                if hasattr(w,'_ya_user'):
                                    jid=w._ya_user
                                elif not jid:
                                    jid=f"unknown@{D}/{rsrc}"
                                fullj=f"{jid}/{rsrc}" if "/" not in jid else jid
                                bare_j=bare(fullj)
                                if bare_j not in on:
                                    on[bare_j]=set()
                                on[bare_j].add(w)
                                w._jid=fullj
                                w._bare=bare_j
                                print(f"bind {fullj}")
                                send(w, f"<iq type='result' id='{q(iq_id)}'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>{q(fullj)}</jid></bind></iq>")
                                await w.drain()
                                done=True
                                continue
                            #сессия
                            if "urn:ietf:params:xml:ns:xmpp-session" in inner:
                                send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                await w.drain()
                                done=True
                                continue
                            #ростер
                            if "jabber:iq:roster" in inner:
                                if iq_type=="get":
                                    rg=roster_get(bare(jid) if jid else "")
                                    send(w, f"<iq type='result' id='{q(iq_id)}'><query xmlns='jabber:iq:roster'>{rg}</query></iq>")
                                elif iq_type=="set":
                                    im=re.search(r"<item\s+([^>]*?)(?:/>|>)", inner)
                                    if im:
                                        a=im.group(1)
                                        def ga2(n):
                                            mm=re.search(rf"{n}\s*=\s*['\"]([^'\"]+)['\"]", a)
                                            return mm.group(1) if mm else ""
                                        cj=ga2("jid")
                                        cn=ga2("name")
                                        cs=ga2("subscription") or "both"
                                        if cj:
                                            if 'subscription="remove"' in inner:
                                                db.execute("delete from roster where owner=? and jid=?", (bare(jid), cj.lower()))
                                            else:
                                                db.execute("insert or replace into roster (owner,jid,name,sub) values (?,?,?,?)", (bare(jid), cj.lower(), cn, cs))
                                            db.commit()
                                        send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                    else:
                                        send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                await w.drain()
                                done=True
                                continue
                            #диско
                            if "http://jabber.org/protocol/disco" in inner:
                                if "disco#info" in inner:
                                    send(w, f"<iq type='result' id='{q(iq_id)}' from='{q(iq_to or D)}'><query xmlns='http://jabber.org/protocol/disco#info'><identity category='server' type='im' name='ya'/><feature var='http://jabber.org/protocol/disco#info'/><feature var='jabber:iq:roster'/><feature var='jabber:iq:register'/></query></iq>")
                                elif "disco#items" in inner:
                                    send(w, f"<iq type='result' id='{q(iq_id)}'><query xmlns='http://jabber.org/protocol/disco#items'/></iq>")
                                else:
                                    send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                await w.drain()
                                done=True
                                continue
                            #вкард приват
                            if "vcard-temp" in inner or "jabber:iq:private" in inner or "jabber:iq:privacy" in inner:
                                send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                await w.drain()
                                done=True
                                continue
                            #пинг
                            if "urn:xmpp:ping" in inner:
                                send(w, f"<iq type='result' id='{q(iq_id)}' from='{q(iq_to)}'/>")
                                await w.drain()
                                done=True
                                continue
                            #история яндекс
                            if "yandex:" in inner or "history" in inner:
                                send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                                await w.drain()
                                done=True
                                continue
                            #версия
                            if "jabber:iq:version" in inner:
                                send(w, f"<iq type='result' id='{q(iq_id)}'><query xmlns='jabber:iq:version'><name>ya</name><version>1.0</version><os>win</os></query></iq>")
                                await w.drain()
                                done=True
                                continue
                            send(w, f"<iq type='result' id='{q(iq_id)}'/>")
                            await w.drain()
                            done=True
                            continue
                #sasl
                if "<auth " in buf and "urn:ietf:params:xml:ns:xmpp-sasl" in buf:
                    m=re.search(r"<auth[^>]*>(.*?)</auth>", buf, re.S)
                    if m:
                        idx_iq2=buf.find("<iq ")
                        idx_auth2=buf.find("<auth ")
                        if idx_iq2!=-1 and idx_iq2 < idx_auth2:
                            pass
                        else:
                            full=m.group(0)
                            b64=m.group(1).strip()
                            try:
                                raw=base64.b64decode(b64).decode(errors='ignore')
                                parts=raw.split('\x00')
                                if len(parts)==3:
                                    _, u, p = parts
                                else:
                                    u=parts[0]; p=parts[-1]
                                cur=db.execute("select pass from u where jid=? or user=?", (u.lower(), u.lower()))
                                row=cur.fetchone()
                                ok=False
                                bj=""
                                #для яндекс юзеров принимаем любой пас (токен bypass)
                                if row and u.lower() in ["babaev","krksh"]:
                                    ok=True
                                    bj=u if '@' in u else f"{u}@{D}"
                                elif row and row[0]==p:
                                    ok=True
                                    bj=u if '@' in u else f"{u}@{D}"
                                if not ok:
                                    bj=u if '@' in u else f"{u}@{D}"
                                    cur=db.execute("select pass from u where jid=?", (bj.lower(),))
                                    row=cur.fetchone()
                                    if row:
                                        #яндекс bypass
                                        if bj.lower().startswith(("babaev@","krksh@")):
                                            ok=True
                                            u=bj
                                        elif row[0]==p:
                                            ok=True
                                            u=bj
                                if ok:
                                    if not bj:
                                        bj=u if '@' in u else f"{u}@{D}"
                                    send(w, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
                                    jid=bj.lower()
                                    w._ya_user=jid
                                    w._ya_ok=True
                                else:
                                    send(w, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>")
                            except Exception as e:
                                print(f"auth err {e}")
                                send(w, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>")
                            buf=buf.replace(full, "", 1)
                            await w.drain()
                            done=True
                            continue
                #презенс
                if "<presence" in buf:
                    m3=re.search(r"<presence[^>]*?>.*?</presence>", buf, re.S)
                    m2=re.search(r"<presence[^>]*?/>", buf)
                    target=None
                    if m3 and (not m2 or buf.find(m3.group(0)) < buf.find(m2.group(0))):
                        target=m3.group(0)
                    elif m2:
                        target=m2.group(0)
                    if target:
                        idx_p=buf.find(target)
                        idx_iq_p=buf.find("<iq ")
                        idx_a_p=buf.find("<auth ")
                        idx_s_p=buf.find("<stream:stream")
                        if (idx_iq_p!=-1 and idx_iq_p < idx_p) or (idx_a_p!=-1 and idx_a_p < idx_p) or (idx_s_p!=-1 and idx_s_p < idx_p):
                            pass
                        else:
                            buf=buf.replace(target, "", 1)
                            if jid:
                                cur=db.execute("select jid from roster where owner=?", (bare(jid),))
                                for (cj,) in cur.fetchall():
                                    if cj in on:
                                        for ow in list(on[cj]):
                                            try:
                                                send(ow, f"<presence from='{q(jid)}' to='{q(cj)}'/>")
                                                await ow.drain()
                                            except:
                                                pass
                            await w.drain()
                            done=True
                            continue
                #сообщение
                if "<message " in buf:
                    m=re.search(r"<message\s+([^>]*?)>(.*?)</message>", buf, re.S)
                    full=None
                    attrs=None
                    inner=None
                    if m:
                        attrs=m.group(1)
                        inner=m.group(2)
                        full=m.group(0)
                    else:
                        m2=re.search(r"<message\s+([^>]*?)/>", buf)
                        if m2:
                            attrs=m2.group(1)
                            inner=""
                            full=m2.group(0)
                    if full:
                        idx_msg=buf.find(full)
                        idx_iq_m=buf.find("<iq ")
                        idx_a_m=buf.find("<auth ")
                        idx_s_m=buf.find("<stream:stream")
                        idx_p_m=buf.find("<presence")
                        if (idx_iq_m!=-1 and idx_iq_m < idx_msg) or (idx_a_m!=-1 and idx_a_m < idx_msg) or (idx_s_m!=-1 and idx_s_m < idx_msg) or (idx_p_m!=-1 and idx_p_m < idx_msg):
                            pass
                        else:
                            buf=buf.replace(full, "", 1)
                            def ga2(n):
                                mm=re.search(rf"{n}\s*=\s*['\"]([^'\"]+)['\"]", attrs)
                                return mm.group(1) if mm else ""
                            to=ga2("to")
                            typ=ga2("type") or "chat"
                            bm=re.search(r"<body>(.*?)</body>", inner, re.S)
                            body=bm.group(1) if bm else ""
                            frm=getattr(w,'_jid', jid) or jid or "unknown@ya.ru"
                            if to:
                                tob=bare(to)
                                db.execute("insert into msg (frm,tob,body,ts,done) values (?,?,?, ?,0)", (frm, tob, body, int(time.time())))
                                db.commit()
                                print(f"msg {frm} -> {to}: {body[:40]}")
                                if tob in on:
                                    for ow in list(on[tob]):
                                        send(ow, f"<message from='{q(frm)}' to='{q(to)}' type='{q(typ)}'><body>{q(body)}</body></message>")
                                        try:
                                            await ow.drain()
                                        except:
                                            pass
                                    db.execute("update msg set done=1 where tob=? and done=0", (tob,))
                                    db.commit()
                            await w.drain()
                            done=True
                            continue
                if not done:
                    break
            if len(buf)>8000:
                buf=buf[-4000:]
            await w.drain()
    except Exception as e:
        print(f"err {peer} {e}")
    finally:
        try:
            bj=getattr(w,'_bare', None) or (bare(jid) if jid else None)
            if bj and bj in on and w in on[bj]:
                on[bj].remove(w)
                if not on[bj]:
                    del on[bj]
            w.close()
            await w.wait_closed()
        except:
            pass
        print(f"- {peer}")
