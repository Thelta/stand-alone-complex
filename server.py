import select
import socket
import argparse

def create_command_parser():
    parser = argparse.ArgumentParser(prog="PROG")
    subparsers = parser.add_subparsers()

    #create subparser for LOGIN_PAGE commands
    parser_login = subparsers.add_parser("\\login")
    parser_login.add_argument("username", type=str)
    parser_login.add_argument("password", type=str)
    parser_login.set_defaults(which="login")

    parser_login = subparsers.add_parser("\\new_user")
    parser_login.add_argument("username", type=str)
    parser_login.add_argument("password", type=str)
    parser_login.set_defaults(which="new_user")

    return parser

def login_user(server_info, socket, user_info):
    is_auth = False

    all_users = server_info["all_users"]
    online = server_info["online_users"]

    username = user_info.username
    password = user_info.password

    if username in all_users:
        if all_users[username] == password:
            is_auth = True
        else:
            is_auth = False #Unnecessary?

    if is_auth:
        socket.send(b"\\login_auth ok")
    else:
        socket.send(b"\\login_auth fail")

    online[socket]["room"] = "ROOM_SELECT"
    online[socket]["username"] = username

def create_new_user(server_info, socket, user_info):
    can_create = False

    all_users = server_info["all_users"]

    username = user_info.username
    password = user_info.password

    if username not in all_users:
        can_create = True
        all_users[username] = password

    if can_create:
        socket.send(b"\\create_acc_info ok")
    else:
        socket.send(b"\\create_acc_info fail")

if __name__ == "__main__":
    #socket variables
    CONN_LIST = []
    PORT_NO = 5000
    RECV_BUFFER = 4096

    users = {"admin" : "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"}
    online_users = dict()
    server_info = {"all_users": users, "online_users": online_users}

    ARG_TYPES = {"LOGIN_PAGE": {"login": login_user, "new_user": create_new_user}}

    com_parser = create_command_parser()

    server_socket = socket.socket()
    #TODO : Use socket.gethostname after finishing server side
    server_socket.bind('localhost', PORT_NO)
    server_socket.listen(10)

    while True:
        read_sockets, write_sockets, error_sockets = select.select(CONN_LIST, [], [])

        for sock in read_sockets:
            #new connection
            if sock == server_socket:
                sockfd, addr = server_socket.accept()
                CONN_LIST.append(sockfd)

                conn_user = dict()
                conn_user["room"] = "LOGIN_PAGE"

                online_users[sockfd] = conn_user

            else:
                try:
                    data = sock.recv(RECV_BUFFER).decode("utf-8")
                    command = data.split(' ')
                    command_info = com_parser.parse_args(command)
                    if command_info.which in ARG_TYPES[online_users[socket]["room"]]:
                        ARG_TYPES[online_users[socket]["room"]](server_info, socket, command_info)
                except:
                    pass

