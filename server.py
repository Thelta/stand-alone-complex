import select
import socket
import argparse
import base64

#TODO all send commands will be exceptions

def create_command_parser():
    parser = argparse.ArgumentParser(prog="PROG")
    subparsers = parser.add_subparsers()

    #create subparser for LOGIN_PAGE commands
    parser_login = subparsers.add_parser("\\login")
    parser_login.add_argument("username", type=str)
    parser_login.add_argument("password", type=str)
    parser_login.set_defaults(which="login")

    parser_nu = subparsers.add_parser("\\new_user")
    parser_nu.add_argument("username", type=str)
    parser_nu.add_argument("password", type=str)
    parser_nu.set_defaults(which="new_user")

    #create subparsers for ROOM_SELECT
    parser_join = subparsers.add_parser("\\join")
    parser_join.add_argument("room_name", type=str)
    parser_join.add_argument("password", nargs='?', type=str)
    parser_join.set_defaults(which="join")

    parser_showr = subparsers.add_parser("\\show_rooms")
    parser_showr.set_defaults(which="show_rooms")

    parser_create = subparsers.add_parser("\\create_room")
    parser_create.add_argument("room_name", type=str)
    parser_create.add_argument("password", nargs='?', type=str)
    parser_create.add_argument("user_limit", nargs='?', type=int)
    parser_create.set_defaults(which="create_room")

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
        online[socket]["room"] = "ROOM_SELECT"
        online[socket]["username"] = username
    else:
        socket.send(b"\\login_auth fail")


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

def show_rooms(server_info, socket, user_info):
    chat_R = server_info["chat_rooms"]
    chat_rooms_string = "Room Name \t\t Password \t Users Online\n\n"   #header
    for room_name, room_info in zip(chat_R.keys(), chat_R.values()):
        first_part = max(0, min(len(room_name), 10))
        second_part = max(10, len(room_name))
        line = room_name + " " * (10 - first_part) + "\t" * ((second_part + 8) // 8 + 1)

        if room_info["password"] is None:
            line = line + " " * 10 + "\t\t" + " "
        else:
            line = line + " " + "*" + " " * 8 + "\t\t" + " "

        line = line + str(len(room_info["users"])) + "/{}".format(room_info["user_limit"]) + "\n"
        chat_rooms_string += line
    base64_string = base64.b64encode(chat_rooms_string.encode())
    send_message = "\\list_rooms_info ok ".encode()  + base64_string
    #base64 because it doesnt feature space.so client side parser wont have difficulty to parse.

    socket.send(send_message)

def create_room(server_info, socket, user_info):
    chat_R = server_info["chat_rooms"]

    room_name = user_info.room_name
    password = user_info.password
    user_limit = user_info.user_limit

    if room_name in chat_R:
        socket.send(b"\\create_room_info fail same_name")
        return

    if len(room_name) > 18:
        socket.send(b"\\create_room_info fail long_name")
        return

    if not 2 < user_limit < 221:    #why 221?Because 4 is too low.
        socket.send(b"\\create_room_info fail user_limit")
        return

    new_room = dict()

    new_room["password"] = password
    new_room["user_limit"] = user_limit
    new_room["users"] = []

    chat_R[room_name] = new_room

    server_info["online_users"][socket]["room"] = room_name

    socket.send(b"\\create_room_info ok")


def join_room(server_info, socket, user_info):
    a = 0

if __name__ == "__main__":
    #socket variables
    CONN_LIST = []
    PORT_NO = 5000
    RECV_BUFFER = 4096

    users = {"admin" : "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"}
    online_users = dict()
    chat_rooms = dict()
    server_info = {"all_users": users, "online_users": online_users, "chat_rooms": chat_rooms}

    ARG_TYPES = {"LOGIN_PAGE": {"login": login_user, "new_user": create_new_user},
                 "ROOM_SELECT": {"join": join_room, "show_rooms": show_rooms, "create_room": create_room}}

    com_parser = create_command_parser()

    server_socket = socket.socket()
    #TODO : Use socket.gethostname after finishing server side
    server_socket.bind(('127.0.0.1', PORT_NO))
    server_socket.listen(10)

    CONN_LIST.append(server_socket)

    print("Listening")

    while True:
        read_sockets, write_sockets, error_sockets = select.select(CONN_LIST, [], [])

        for sock in read_sockets:
            #new connection
            if sock == server_socket:
                sockfd, addr = server_socket.accept()
                CONN_LIST.append(sockfd)

                print("Someone connected.")

                conn_user = dict()
                conn_user["room"] = "LOGIN_PAGE"

                online_users[sockfd] = conn_user
            #TODO control user
            else:
                try:
                    data = sock.recv(RECV_BUFFER).decode("utf-8")
                    command = data.rstrip().split(' ')
                    command_info = com_parser.parse_known_args(command)[0]
                    if command_info.which in ARG_TYPES[online_users[sock]["room"]]:
                        ARG_TYPES[online_users[sock]["room"]][command_info.which](server_info, sock, command_info)
                except:
                    pass

