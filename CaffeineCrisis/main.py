import socket
import struct
import time

#flag{c@fF3iNe_ov3rfl0W_DEteCt3d}

MESSAGE_TYPE_ORDER = 1
MESSAGE_TYPE_RESPONSE = 2
MESSAGE_TYPE_SECRET = 3

COFFEE_TYPE = {
    5: 'Rainbow Unicorn Frappe',
    0: 'Espresso',
    1: 'Latte',
    2: 'Cappuccino',
    3: 'Cold Brew',
    4: 'Americano'
}

user_quotas = {}

INITIAL_QUOTA = 5

def xor_obfuscate(data, key):
    return bytes([b ^ key for b in data])

def calculate_checksum(data):
    checksum = 0
    for byte in data:
        checksum += byte
    return checksum & 0xFFFFFFFF

def xor_obfuscate_flag(flag, user_id):
    key = user_id & 0xFF
    obfuscated_flag = xor_obfuscate(flag.encode(), 0xFF)
    return obfuscated_flag

def handle_client(client_socket):
    base_message_format = '<B H 256s I'

    coffee_order_format = '<Q I B i'

    response_format = '<B I'

    flag_response_format = '<B 64s'

    try:
        while True:
            data = client_socket.recv(struct.calcsize(base_message_format))
            if len(data) == 0:
                print("Client disconnected.")
                break
            if len(data) != struct.calcsize(base_message_format):
                print("Incomplete data received!")
                break

            message_type, data_length, data_field, received_checksum = struct.unpack(base_message_format, data)

            calculated_checksum = calculate_checksum(data[:-4])

            if calculated_checksum != received_checksum:
                print(f"Checksum mismatch! Calculated: {calculated_checksum}, Received: {received_checksum}")
                continue

            if message_type == MESSAGE_TYPE_ORDER:
                coffee_order = struct.unpack(coffee_order_format, data_field[:struct.calcsize(coffee_order_format)])
                timestamp, user_id, coffee_type, quantity = coffee_order

                if user_id not in user_quotas:
                    user_quotas[user_id] = INITIAL_QUOTA

                if coffee_type == 5:
                    secret_flag = "flag{t4sT3_tH3_uNiC0rN_r4iNb0W}"
                    obfuscated_flag = xor_obfuscate_flag(secret_flag, user_id)
                    flag_message = struct.pack(flag_response_format, 1, obfuscated_flag)

                    message_length = len(obfuscated_flag)
                    response_message = struct.pack(base_message_format, MESSAGE_TYPE_SECRET, message_length, flag_message, 0)

                    response_checksum = calculate_checksum(response_message[:-4])
                    response_message = struct.pack(base_message_format, MESSAGE_TYPE_SECRET, message_length, flag_message, response_checksum)

                    client_socket.send(response_message)
                    print(f"Sent XOR-obfuscated secret flag to user {user_id}")
                    continue

                remaining_quota = user_quotas[user_id]

                if quantity > remaining_quota:
                    status = 0  
                    print(f"Order failed: User {user_id} tried to order {quantity} coffees, but only {remaining_quota} left.")
                else:
                    status = 1  
                    prev_quota = remaining_quota
                    remaining_quota -= quantity
                    if remaining_quota > prev_quota:
                        secret_flag = "flag{c@fF3iNe_ov3rfl0W_DEteCt3d}"
                        obfuscated_flag = xor_obfuscate_flag(secret_flag, user_id)
                        flag_message = struct.pack(flag_response_format, 1, obfuscated_flag)

                        message_length = len(obfuscated_flag)
                        response_message = struct.pack(base_message_format, MESSAGE_TYPE_SECRET, message_length, flag_message, 0)

                        response_checksum = calculate_checksum(response_message[:-4])
                        response_message = struct.pack(base_message_format, MESSAGE_TYPE_SECRET, message_length, flag_message, response_checksum)

                        client_socket.send(response_message)
                        print(f"Sent XOR-obfuscated secret flag to user {user_id}")
                    
                    user_quotas[user_id] = remaining_quota
                    print(f"Coffee Type:{coffee_type}")
                    print(f"Order successful: User {user_id} ordered {quantity} {COFFEE_TYPE.get(coffee_type, 'Unknown')}(s). Remaining quota: {remaining_quota}")

                response_data = struct.pack(response_format, status, remaining_quota)

                message_length = len(response_data)
                response_message = struct.pack(base_message_format, MESSAGE_TYPE_RESPONSE, message_length, response_data, 0)

                response_checksum = calculate_checksum(response_message[:-4])
                response_message = struct.pack(base_message_format, MESSAGE_TYPE_RESPONSE, message_length, response_data, response_checksum)

                client_socket.send(response_message)

    except (ConnectionResetError, BrokenPipeError):
        print("Client forcibly closed the connection.")
    finally:
        client_socket.close()

def start_server(ip, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    print(f"Server is listening on port {port}...")

    while True:
        try:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            handle_client(client_socket)
        except Exception as e:
            print(f"Error accepting client: {e}")
            continue

if __name__ == '__main__':
    start_server('0.0.0.0', 42069)
