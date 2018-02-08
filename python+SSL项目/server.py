import socket
import ssl,time
sock=socket.socket()
print("建立套接字成功")
sock.bind(("127.0.0.1", 443))
print("绑定成功")
sock.listen(1)
def input_pro(connstream,data):
    print("接收到的客户端数据长度是",len(data))
    return True
def doclient(connstream):
    recvtime=0
    sendtime=0
    n=0
    t1=time.clock()
    data=connstream.recv(1024)
    t2=time.clock()
    print("服务端接收客户端数据的时间",t2-t1)
    while data:
        if not input_pro(connstream,data):
            break
        n=n+1
        t3 = time.clock()
        connstream.send(b'b' * 1000)
        t4 = time.clock()

        sendtime += t4 - t3
        print("服务端发送数据时长", t4 - t3)

        t3 = time.clock()
        data = connstream.recv(1024)
        t4 = time.clock()
        recvtime += t4 - t3
        print("服务端接收客户端数据时间", t4 - t3)

    print("平均发送时间是",sendtime/n,"平均接收时间是",recvtime/n,)
    return True
while True:
    #接受连接并返回（conn,address）,
    # 其中conn是新的套接字对象，
    # 可以用来接收和发送数据。
    # address是连接客户端的地址。
    conn,addr=sock.accept()
    print("客户端的套接字数据接收到了")
    connstream=ssl.wrap_socket(conn,"key.pem","cert.pem",server_side=True)
    try:
        doclient(connstream)
    finally:
        connstream.shutdown(socket.SHUT_RDWR)
        connstream.close()





