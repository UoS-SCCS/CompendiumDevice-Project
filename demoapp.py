import json
from compendium.client import Compendium
from compendium.storage import KeyRingIdentityStore
from compendium.utils import B64
nonce = None
app_pk = None
encrypted_response = None
def mycallback(response,error=None):
    global nonce
    global app_pk
    global encrypted_response
    if error is not None:
        print(error)
        return
    
    print(response)
    if "type" in response:
        if response["type"] == "Reg":
            app_pk = response["app_pk"]
            print("Key Received:" + app_pk)
        elif response["type"]=="Verify":
            print("Signature Verified:" + str(compendium.verify_signature(response["app_sig"],nonce,app_pk)))
        elif response["type"]=="Put":
            encrypted_response=response["encdata"]
            print("Encrypted data:" + encrypted_response)
        elif response["type"]=="Get":
            plaintext = B64.decode(response["data"]).decode("UTF-8")
            print("Received Plaintext:" + plaintext)


compendium = Compendium()

import os
def clear():
    os.system('cls||clear')
def print_welcome():
    print("**************************************")
    print("*       Compendium Test Client       *")
    print("*                                    *")
    print("**************************************")
def select_device():
    message = "Select companion device:\n\n"
    counter = 0
    for name in compendium.get_enrolled_devices():
        message += "\t" + str(counter) + " " + name + "\n"
        counter += 1
    message += "\n\te Enrol New\n\n>"
    device_idx = input(message)
    if device_idx == "e":
        compendium.enrol_new_device(mycallback)
    else:
        return compendium.get_enrolled_devices()[int(device_idx)]

def choose_option():
    message = "Select operation:\n\n"
    message += "\t1 Register for Verification\n"
    message += "\t2 Perform Verification\n"
    message += "\t3 Perform Put\n"
    message += "\t4 Perform Get\n"
    user_input = input(message)
    while user_input=="":
        user_input = input(message)
    option = int(user_input)
    compendium.reset()
    if option == 1:
        compendium.register_user_verification(target_device,"TestSignatureApp","Testing the protocol", mycallback)
    elif option ==2:
        global nonce
        nonce = compendium.perform_user_verification(target_device,"TestSignatureApp","Testing the protocol","12345",mycallback)
    elif option ==3:
        data = enter_plaintext()
        compendium.put_data(data.encode("UTF-8"),target_device,"TestDataApp","Testing the protocol","12345",mycallback)
    elif option ==4:
        global encrypted_response
        compendium.get_data(json.loads(encrypted_response),target_device,"TestDataApp","Testing the protocol","12345",mycallback)
        

def enter_plaintext():
    userinput = input("Please enter a plaintext you would like encrypted:\n>")
    return userinput

def response_wait():
    userinput = input("Response will appear below. (Press x to exit or any other key to continue)")
    if userinput == "x":
        exit(0)
    work_loop()
    
def work_loop():
    clear()
    choose_option()
    response_wait()

clear()
print_welcome()
target_device = select_device()
work_loop()
