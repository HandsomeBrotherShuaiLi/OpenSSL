import socket, ssl, pprint, time
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
ssl_s=ssl.wrap_socket(s,cert_reqs=ssl.CERT_REQUIRED,ca_certs="cert.pem")
ssl_s.connect(("127.0.0.1", 443))
print("套接字连接成功")
n=0
sendtime=0
recvtime=0
while n<6:
    n=n+1
    t1=time.clock()
    ssl_s.send(b'a'*100)
    t2=time.clock()
    sendtime+=t2-t1
    print("发送时长",t2-t1)
    t1=time.clock()
    data=ssl_s.recv(1024)
    t2=time.clock()
    recvtime+=t2-t1
    print("接收时长",t2-t1)
    print(len(data))
print("平均接收时间",sendtime/n,"平均发送时间",recvtime/n)
print("生成的证书信息")
pprint.pprint(ssl_s.getpeercert())
ssl_s.close()