import http.server, ssl, threading, os

#хттп для яндекса
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        #логи
        print(f"http {self.path}")
        if "genauthtoken" in self.path:
            #возвращаем токен admin
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            #яхт ждет что-то типа токена, отдаем admin
            self.wfile.write(b"admin")
        elif "xmppresolve" in self.path:
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.end_headers()
            #отдаем хмпп инфо для ya.ru
            self.wfile.write(b'<response><xmpp><host>127.0.0.1</host><port>5222</port></xmpp></response>')
        elif "passport" in self.path:
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
    def log_message(self, format, *args):
        pass

def run():
    #хттп 8080
    try:
        s=http.server.HTTPServer(("127.0.0.1", 8080), H)
        t=threading.Thread(target=s.serve_forever, daemon=True)
        t.start()
        print("http 8080 up")
    except Exception as e:
        print(f"http 8080 fail {e}")

    #хттпс 443 с самоподписанным
    cert = "cert.pem"
    key = "key.pem"
    if not os.path.exists(cert):
        #генерим через cryptography если есть, иначе openssl
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            k=rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subj=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1")])
            c=x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(k.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__('ipaddress').ip_address("127.0.0.1"))]), critical=False).sign(k, hashes.SHA256())
            open(key,"wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            open(cert,"wb").write(c.public_bytes(serialization.Encoding.PEM))
            print("gen cert ok")
        except Exception as e:
            print(f"gen cert fail {e}")
            return
    try:
        s2=http.server.HTTPServer(("127.0.0.1", 8443), H)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        s2.socket=ctx.wrap_socket(s2.socket, server_side=True)
        t2=threading.Thread(target=s2.serve_forever, daemon=True)
        t2.start()
        print("https 8443 up")
    except Exception as e:
        print(f"https fail {e}")

if __name__=="__main__":
    run()
    import time
    while True:
        time.sleep(1)
